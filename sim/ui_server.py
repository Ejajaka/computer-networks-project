#!/usr/bin/env python3
"""
Live DDoS mitigation Simulator UI.

- Starts the attacker flooding for 2 minutes (continuous).
- Lets you toggle the eBPF/XDP filter ON and OFF live from the browser.
- Shows, in real time:
      * Packets hitting the NIC   (victim eth0 rx)
      * Packets reaching the app  (victim IP InReceives, i.e. AFTER XDP)
      * Drop rate
  ...so you can SEE the difference the filter makes, live.

Run:   python3 sim/ui_server.py
Open:  http://localhost:8090
(No sudo needed - uses the docker group. `docker exec` runs as root in-container.)
"""
import http.server
import json
import os
import subprocess
import threading
import time
import re

PORT = 8090
VICTIM = "victim"
ATTACKER = "attacker"
VICTIM_IP = "172.30.0.10"
PIN = "/sys/fs/bpf/ddos/xdp"
FLOOD_SECONDS = 120          # 2 minutes continuous flood
HISTORY = 120                # samples kept for the chart

# ---------------------------------------------------------------- state
lock = threading.Lock()
state = {
    "flood_running": False,
    "flood_remaining": 0,
    "filter_on": False,
    "nic_pps": 0,
    "app_pps": 0,
    "drop_pct": 0.0,
    "seen_total": 0,
    "normal_running": False,
    "normal_status": "idle",
    "normal_loss": None,
    "history": [],           # list of {t, nic, app}
}


# ---------------------------------------------------------------- helpers
def sh(cmd, timeout=15):
    """Run a shell command, return stdout."""
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout).stdout
    except Exception:
        return ""


def bpf_path():
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1'").strip()
    return out or "bpftool"


def read_nic_pkts():
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'cat /proc/net/dev | grep eth0 | awk \"{{print \\$3}}\"'").strip()
    return int(out) if out.isdigit() else None


def read_app_pkts():
    # Ip: InReceives (field 4 on the value line) -> counts packets AFTER XDP
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'grep \"^Ip:\" /proc/net/snmp | tail -1 | awk \"{{print \\$4}}\"'").strip()
    return int(out) if out.isdigit() else None


def filter_is_on():
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'ip link show eth0 | grep -q xdp && echo ON || echo OFF'").strip()
    return out == "ON"


PROJECT_DIR = None  # set in __main__


def prepare():
    """Make sure containers run, tools exist, program is copied, server is up."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
    sh("docker start victim attacker benign")
    # install tools in victim if missing
    sh(f"docker exec {VICTIM} bash -c 'command -v iptables >/dev/null 2>&1 || "
       f"(apt-get update -qq && apt-get install -y -qq iptables) ; "
       f"ls /usr/lib/linux-tools/*/bpftool >/dev/null 2>&1 || "
       f"(apt-get update -qq && apt-get install -y -qq linux-tools-generic linux-tools-common)'")
    # copy the compiled program (engine/ is the eBPF source dir)
    src = f"{root}/engine/ddos_filter_kern.o"
    if not os.path.exists(src):
        src = f"{root}/ebpf/ddos_filter_kern.o"
    sh(f"docker cp {src} {VICTIM}:/tmp/ddos_filter_kern.o")
    # start the victim's service
    sh(f"docker exec -d {VICTIM} bash -c 'pkill -9 iperf3 2>/dev/null; iperf3 -s -p 5201'")


def attach_filter():
    bpf = bpf_path()
    # load (if needed) and attach
    sh(f"docker exec {VICTIM} bash -c '"
       f"if [ ! -e {PIN} ]; then rm -rf /sys/fs/bpf/ddos; "
       f"{bpf} prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos; fi; "
       f"ip link set dev eth0 xdp pinned {PIN}'")
    return filter_is_on()


def detach_filter():
    sh(f"docker exec {VICTIM} bash -c 'ip link set dev eth0 xdp off'")
    return not filter_is_on()


def start_flood():
    sh(f"docker exec {ATTACKER} bash -c 'pkill -9 hping3 2>/dev/null; true'")
    for _ in range(4):
        sh(f"docker exec -d {ATTACKER} hping3 -2 -p 5201 --flood {VICTIM_IP}")


def stop_flood():
    sh(f"docker exec {ATTACKER} bash -c 'pkill -9 hping3 2>/dev/null; true'")


# ---------------------------------------------------------------- poller thread
def poll_loop():
    prev_nic = read_nic_pkts()
    prev_app = read_app_pkts()
    last_t = time.time()
    while True:
        time.sleep(1)
        now = read_nic_pkts()
        app = read_app_pkts()
        t = time.time()
        dt = max(t - last_t, 0.001)
        if now is not None and prev_nic is not None:
            nic_pps = int((now - prev_nic) / dt)
        else:
            nic_pps = 0
        if app is not None and prev_app is not None:
            app_pps = max(int((app - prev_app) / dt), 0)
        else:
            app_pps = 0
        prev_nic, prev_app, last_t = now, app, t

        on = filter_is_on()
        drop = 0.0
        if on and nic_pps > 0:
            drop = round(100.0 * max(nic_pps - app_pps, 0) / nic_pps, 1)

        with lock:
            state["filter_on"] = on
            state["nic_pps"] = nic_pps
            state["app_pps"] = app_pps
            state["drop_pct"] = drop
            state["history"].append({"t": time.strftime("%H:%M:%S"),
                                     "nic": nic_pps, "app": app_pps})
            if len(state["history"]) > HISTORY:
                state["history"].pop(0)


# ---------------------------------------------------------------- flood thread
def flood_loop():
    """Keeps the flood running for FLOOD_SECONDS, then stops."""
    end = time.time() + FLOOD_SECONDS
    start_flood()
    while time.time() < end:
        with lock:
            if not state["flood_running"]:
                stop_flood()
                return
            state["flood_remaining"] = int(end - time.time())
        time.sleep(1)
        # keep workers alive (relaunch if any died)
        n = sh(f"docker exec {ATTACKER} bash -c 'pgrep -c hping3 || true'").strip()
        if not n.isdigit() or int(n) < 4:
            for _ in range(4 - (int(n) if n.isdigit() else 0)):
                sh(f"docker exec -d {ATTACKER} hping3 -2 -p 5201 --flood {VICTIM_IP}")
    stop_flood()
    with lock:
        state["flood_running"] = False
        state["flood_remaining"] = 0


# ---------------------------------------------------------------- normal traffic
def normal_loop():
    """Runs a legitimate user's traffic (iperf3 from benign) in a loop and
    reports the packet loss. Normal traffic should NOT be dropped."""
    while True:
        with lock:
            if not state["normal_running"]:
                break
        out = sh(f"docker exec benign iperf3 -c {VICTIM_IP} -p 5201 -u -b 3M "
                 f"-t 4 --json", timeout=20)
        try:
            j = json.loads(out)
            s = j["end"]["sum"]
            loss = round(s.get("lost_percent", 0.0), 1)
            mbps = s.get("bits_per_second", 0) / 1e6
            with lock:
                state["normal_loss"] = loss
                state["normal_status"] = f"{mbps:.1f} Mbps, {loss:.1f}% loss"
        except Exception:
            with lock:
                state["normal_status"] = "running..."
        time.sleep(0.5)
    with lock:
        state["normal_running"] = False
        state["normal_status"] = "idle"
        state["normal_loss"] = None


# ---------------------------------------------------------------- HTTP
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>DDoS Mitigation Simulator</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;background:#0b1220;color:#e2e8f0;margin:0;padding:24px}
 h1{font-size:22px;margin:0 0 2px}.sub{color:#94a3b8;font-size:13px;margin-bottom:18px}
 .row{display:flex;gap:16px;flex-wrap:wrap;align-items:stretch}
 .card{background:#131f36;border:1px solid #274060;border-radius:14px;padding:18px 20px;flex:1;min-width:190px}
 .label{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px}
 .value{font-size:30px;font-weight:700;margin-top:6px}
 .app{color:#34d399}.nic{color:#60a5fa}.drop{color:#f87171}
 .controls{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
 <button{font-size:15px;font-weight:600;border:0;border-radius:10px;padding:12px 22px;cursor:pointer;color:#fff}
 .start{background:#2563eb}.stop{background:#475569}
 .tog{background:#334155}.tog.on{background:#059669}
 .normal{background:#7c3aed}.normal.on{background:#b45309}
 button:disabled{opacity:.5;cursor:not-allowed}
 canvas{background:#131f36;border:1px solid #274060;border-radius:14px;width:100%;margin-top:8px}
 .legend{font-size:13px;color:#94a3b8;margin-top:6px}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
 .status{font-size:13px;color:#cbd5e1;margin-top:14px}
 .pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700}
 .pill.on{background:#064e3b;color:#6ee7b7}.pill.off{background:#4c1d24;color:#fca5a5}
</style></head><body>
<h1>eBPF/XDP DDoS Mitigation — Live Simulator</h1>
<div class="sub">Attacker floods the victim for 2 minutes. Toggle the filter ON/OFF and watch the effect live.</div>

<div class="row">
  <div class="card"><div class="label">Packets hitting NIC</div><div class="value nic" id="nic">--</div><div class="label">per second (before XDP)</div></div>
  <div class="card"><div class="label">Packets reaching app</div><div class="value app" id="app">--</div><div class="label">per second (after XDP)</div></div>
  <div class="card"><div class="label">Drop rate</div><div class="value drop" id="drop">--</div><div class="label">dropped at the NIC</div></div>
  <div class="card"><div class="label">Normal traffic (legit)</div><div class="value" id="normal" style="font-size:22px">idle</div><div class="label">must NOT be dropped</div></div>
</div>

<div class="controls">
  <button class="start" id="floodBtn" onclick="toggleFlood()">Start 2-minute Flood</button>
  <button class="tog" id="filterBtn" onclick="toggleFilter()">Filter: OFF</button>
  <button class="normal" id="normalBtn" onclick="toggleNormal()">Start Normal Traffic</button>
</div>
<div class="status">Flood: <span id="floodState">idle</span> &nbsp;|&nbsp; Countdown: <span id="cd">--</span>s &nbsp;|&nbsp; Filter: <span id="fpill" class="pill off">OFF</span></div>

<h2 style="font-size:15px;margin:22px 0 0">Live traffic (packets/sec)</h2>
<canvas id="chart" height="170"></canvas>
<div class="legend"><span class="dot" style="background:#60a5fa"></span>NIC (before XDP)
 &nbsp;&nbsp;<span class="dot" style="background:#34d399"></span>App (after XDP)</div>

<script>
let hist=[];
function nf(n){return (n||0).toLocaleString();}
async function getState(){const r=await fetch('/api/state');return r.json();}
async function toggleFilter(){const s=await getState();await fetch('/api/filter/'+(s.filter_on?'off':'on'),{method:'POST'});refresh();}
async function toggleFlood(){const s=await getState();await fetch('/api/flood/'+(s.flood_running?'stop':'start'),{method:'POST'});refresh();}
async function toggleNormal(){const s=await getState();await fetch('/api/normal/'+(s.normal_running?'stop':'start'),{method:'POST'});refresh();}

function draw(){
 const c=document.getElementById('chart'),ctx=c.getContext('2d');
 const w=c.width=c.clientWidth, h=c.height;
 ctx.clearRect(0,0,w,h);
 const max=Math.max(1000,...hist.map(s=>Math.max(s.nic,s.app)));
 ctx.strokeStyle='#274060';ctx.fillStyle='#64748b';ctx.font='10px sans-serif';
 for(let g=0;g<=4;g++){const y=h-g*h/4;ctx.beginPath();ctx.moveTo(40,y);ctx.lineTo(w,y);ctx.stroke();
   ctx.fillText(nf(Math.round(max*g/4)),2,y-3);}
 if(hist.length<2)return;
 const step=(w-40)/(hist.length-1);
 for(const [k,col] of [['nic','#60a5fa'],['app','#34d399']]){
   ctx.strokeStyle=col;ctx.lineWidth=2;ctx.beginPath();
   hist.forEach((s,i)=>{const x=40+i*step,y=h-(s[k]/max)*h; i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
   ctx.stroke();
 }
}
async function refresh(){
 try{
  const s=await getState();
  document.getElementById('nic').textContent=nf(s.nic_pps);
  document.getElementById('app').textContent=nf(s.app_pps);
  document.getElementById('drop').textContent=s.filter_on?s.drop_pct+'%':'OFF';
  document.getElementById('filterBtn').textContent='Filter: '+(s.filter_on?'ON':'OFF');
  document.getElementById('filterBtn').className='tog'+(s.filter_on?' on':'');
  document.getElementById('fpill').textContent=s.filter_on?'ON':'OFF';
  document.getElementById('fpill').className='pill '+(s.filter_on?'on':'off');
  document.getElementById('floodState').textContent=s.flood_running?'RUNNING':'idle';
  document.getElementById('cd').textContent=s.flood_running?s.flood_remaining:'--';
  document.getElementById('floodBtn').textContent=s.flood_running?'Stop Flood':'Start 2-minute Flood';
  document.getElementById('floodBtn').className=s.flood_running?'stop':'start';
  const nb=document.getElementById('normalBtn');
  nb.textContent=s.normal_running?'Stop Normal Traffic':'Start Normal Traffic';
  nb.className='normal'+(s.normal_running?' on':'');
  const nel=document.getElementById('normal');
  nel.textContent=s.normal_status;
  if(s.normal_running && s.normal_loss!==null){nel.style.color=s.normal_loss>5?'#f87171':'#34d399';}
  else{nel.style.color='#e2e8f0';}
  hist=s.history||[];draw();
 }catch(e){}
}
setInterval(refresh,1000);refresh();
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/html"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/state":
            with lock:
                data = dict(state)
            self._send(json.dumps(data), "application/json")
        else:
            self._send(PAGE)

    def do_POST(self):
        if self.path.startswith("/api/filter/"):
            want = self.path.rsplit("/", 1)[-1]
            if want == "on":
                attach_filter()
            else:
                detach_filter()
            self._send(json.dumps({"ok": True}), "application/json")
        elif self.path.startswith("/api/flood/"):
            want = self.path.rsplit("/", 1)[-1]
            with lock:
                if want == "start" and not state["flood_running"]:
                    state["flood_running"] = True
                    threading.Thread(target=flood_loop, daemon=True).start()
                elif want == "stop":
                    state["flood_running"] = False
            self._send(json.dumps({"ok": True}), "application/json")
        elif self.path.startswith("/api/normal/"):
            want = self.path.rsplit("/", 1)[-1]
            with lock:
                if want == "start" and not state["normal_running"]:
                    state["normal_running"] = True
                    state["normal_status"] = "running..."
                    threading.Thread(target=normal_loop, daemon=True).start()
                elif want == "stop":
                    state["normal_running"] = False
            self._send(json.dumps({"ok": True}), "application/json")
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    prepare()
    threading.Thread(target=poll_loop, daemon=True).start()
    print(f"Simulator UI:  http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        stop_flood()
        print("\nStopped.")