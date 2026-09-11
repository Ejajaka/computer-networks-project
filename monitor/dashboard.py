#!/usr/bin/env python3
"""
Live web dashboard for the eBPF/XDP DDoS mitigation project.

Reads the victim container's XDP stats map and serves a browser page that
shows the drop rates (UDP / SYN / combined) live, with charts.

Run:  sudo python3 monitor/dashboard.py
Then open:  http://localhost:8080
"""
import http.server
import json
import re
import subprocess
import threading
import time

PORT = 8080
HISTORY = 120  # number of samples kept for the chart
VICTIM = "victim"

# ------------------------------------------------ stats reading
def bpftool_path():
    """Find bpftool inside the victim container (version independent)."""
    try:
        out = subprocess.run(
            ["docker", "exec", VICTIM, "bash", "-c",
             "ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1"],
            capture_output=True, text=True, timeout=10).stdout.strip()
        return out or "bpftool"
    except Exception:
        return "bpftool"


def read_stats():
    """Return dict with udp_total/udp_dropped/syn_total/syn_dropped."""
    bpf = bpftool_path()
    cmd = f"docker exec {VICTIM} bash -c \"{bpf} map dump name stats_map 2>/dev/null\""
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        return None
    s = {"udp_total": 0, "udp_dropped": 0, "syn_total": 0, "syn_dropped": 0}
    for m in re.finditer(r'"(udp_total|udp_dropped|syn_total|syn_dropped)":\s*(\d+)', out):
        s[m.group(1)] = s.get(m.group(1), 0) + int(m.group(2))
    return s


# ------------------------------------------------ history (for the chart)
history = []          # list of {"t": ts, "udp": pct, "syn": pct}
last_stats = {}
lock = threading.Lock()

def poll_loop():
    global last_stats
    prev = read_stats() or {}
    while True:
        time.sleep(2)
        cur = read_stats()
        if not cur:
            continue
        sample = {"t": time.strftime("%H:%M:%S")}
        for k in ("udp", "syn"):
            t = cur[k + "_total"] - prev.get(k + "_total", 0)
            d = cur[k + "_dropped"] - prev.get(k + "_dropped", 0)
            sample[k] = round(100 * d / t, 1) if t > 0 else None
        with lock:
            history.append(sample)
            if len(history) > HISTORY:
                history.pop(0)
            last_stats = {
                "udp_total": cur["udp_total"],
                "udp_dropped": cur["udp_dropped"],
                "syn_total": cur["syn_total"],
                "syn_dropped": cur["syn_dropped"],
                "udp_pct": round(100 * cur["udp_dropped"] / cur["udp_total"], 1)
                           if cur["udp_total"] else 0,
                "syn_pct": round(100 * cur["syn_dropped"] / cur["syn_total"], 1)
                           if cur["syn_total"] else 0,
            }
        prev = cur


# ------------------------------------------------ web server
PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DDoS Mitigation — Live Dashboard</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#0f172a; color:#e2e8f0;
         margin:0; padding:24px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:#94a3b8; font-size:13px; margin-bottom:20px; }
  .cards { display:flex; gap:16px; flex-wrap:wrap; }
  .card { background:#1e293b; border:1px solid #334155; border-radius:12px;
          padding:18px 22px; min-width:210px; flex:1; }
  .card .label { color:#94a3b8; font-size:13px; text-transform:uppercase; letter-spacing:1px; }
  .card .value { font-size:34px; font-weight:700; margin-top:6px; }
  .card .detail { color:#cbd5e1; font-size:13px; margin-top:6px; }
  .good { color:#34d399; } .bad { color:#f87171; }
  .bar-wrap { margin-top:12px; height:10px; background:#0f172a; border-radius:6px; overflow:hidden; }
  .bar { height:100%; border-radius:6px; transition:width .5s; }
  .green { background:linear-gradient(90deg,#10b981,#34d399); }
  .red { background:linear-gradient(90deg,#ef4444,#f87171); }
  h2 { font-size:15px; margin:24px 0 8px; color:#f1f5f9; }
  canvas { background:#1e293b; border:1px solid #334155; border-radius:12px; width:100%; }
  .status { color:#94a3b8; font-size:12px; margin-top:16px; }
</style>
</head>
<body>
  <h1>eBPF/XDP DDoS Mitigation — Live Dashboard</h1>
  <div class="sub">Live packet-drop stats from the victim container's XDP filter
      (refreshes every 2 seconds)</div>

  <div class="cards">
    <div class="card">
      <div class="label">UDP Flood Drop Rate</div>
      <div class="value" id="udp-pct">--</div>
      <div class="detail" id="udp-det">waiting for traffic...</div>
      <div class="bar-wrap"><div class="bar green" id="udp-bar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="label">SYN Flood Drop Rate</div>
      <div class="value" id="syn-pct">--</div>
      <div class="detail" id="syn-det">waiting for traffic...</div>
      <div class="bar-wrap"><div class="bar red" id="syn-bar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="label">Combined Drop Rate</div>
      <div class="value" id="comb-pct">--</div>
      <div class="detail">UDP + SYN floods together</div>
    </div>
  </div>

  <h2>Drop rate over time (%)</h2>
  <canvas id="chart" height="160"></canvas>
  <div class="status" id="status">Connected</div>

<script>
const ctx = document.getElementById('chart').getContext('2d');
let hist = [];
function fmt(n){ return (n===null||n===undefined)?'--':n.toFixed(1)+'%'; }

function draw(){
  ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
  const w=ctx.canvas.width, h=ctx.canvas.height;
  ctx.strokeStyle='#334155'; ctx.lineWidth=1;
  for(let g=0; g<=4; g++){
    const y=h-g*h/4;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
    ctx.fillStyle='#64748b'; ctx.font='10px sans-serif';
    ctx.fillText((100-g*25)+'%',4,y-3);
  }
  if(hist.length<2) return;
  const step=w/(hist.length-1);
  for(const [key,col] of [['udp','#34d399'],['syn','#f87171']]){
    ctx.strokeStyle=col; ctx.lineWidth=2; ctx.beginPath();
    hist.forEach((s,i)=>{
      const v=s[key]; if(v===null||v===undefined) return;
      const x=i*step, y=h-(v/100)*h;
      i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
    });
    ctx.stroke();
  }
}

async function refresh(){
  try{
    const r=await fetch('/api/stats');
    const d=await r.json();
    document.getElementById('udp-pct').textContent=fmt(d.udp_pct);
    document.getElementById('syn-pct').textContent=fmt(d.syn_pct);
    const tot=d.udp_total+d.syn_total, dro=d.udp_dropped+d.syn_dropped;
    document.getElementById('comb-pct').textContent=tot?fmt(100*dro/tot):'--';
    document.getElementById('udp-det').textContent =
      d.udp_total+' seen, '+d.udp_dropped+' dropped';
    document.getElementById('syn-det').textContent =
      d.syn_total+' seen, '+d.syn_dropped+' dropped';
    document.getElementById('udp-bar').style.width=(d.udp_pct||0)+'%';
    document.getElementById('syn-bar').style.width=(d.syn_pct||0)+'%';
    hist=d.history||[]; draw();
    document.getElementById('status').textContent='Connected - '+d.time;
  }catch(e){
    document.getElementById('status').textContent='Disconnected - retrying...';
  }
}
setInterval(refresh,2000); refresh();
</script>
</body>
</html>
"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/stats":
            with lock:
                data = {
                    "time": time.strftime("%H:%M:%S"),
                    "history": list(history),
                    **last_stats,
                }
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"Dashboard running:  http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=poll_loop, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")