#!/usr/bin/env python3
"""Backend for the live DDoS simulator.

Simple flow:

    browser button
        -> HTTP request to this file
        -> start/stop a flood or attach/detach XDP
        -> XDP handles every incoming packet
        -> this file reads the counters every second
        -> browser receives JSON and updates the page

This file also contains the complete browser page in PAGE below. Therefore the
simulator has two files: start_ui.sh starts this file, and this file runs the
backend plus the embedded HTML/CSS/JavaScript frontend.

The real packet decision is made by engine/ddos_filter_kern.c, compiled into
ddos_filter_kern.o. This Python file controls that filter, reads its stats_map,
calculates the displayed model result, and serves the browser.

Run: python3 sim/ui_server.py   ->   http://localhost:8090
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
PIN = "/sys/fs/bpf/ddos/xdp"  #filesystem path where the loaded eBPF program is pinned.
FLOOD_SECONDS = 120          # 2 minutes continuous flood
HISTORY = 120                # samples kept for the chart

# ---------------------------------------------------------------- state
# Shared state is read by the HTTP thread and written by the poller/worker
# threads. The lock prevents the browser from seeing half-updated values.
lock = threading.Lock()
flood_lock = threading.Lock()
state = {
    "flood_running": False,
    "flood_mode": None,       # "udp", "syn", or "both" while a flood runs
    "flood_gen": 0,           # invalidates stale flood threads
    "flood_remaining": 0,
    "filter_on": False,
    "nic_pps": 0,  # packets reaching NIC
    "app_pps": 0,  # packets reaching application
    "drop_pct": 0.0,  # drop percentage
    "seen_total": 0,  # total packets to be seen
    "normal_running": False,
    "normal_status": "idle",
    "normal_loss": None,
    "history": [],           # list of {t, nic, app}
    "model": None,           # backend rate-limiter model (real XDP counters)
    "resources": {
        "cpu_pct": 2.0,
        "memory": {"used_pct": 6.2, "used_mb": 32.0, "total_mb": 512.0},
        "gpu": {"available": False},
        "source": "victim-load-model",
    },
}


# ---------------------------------------------------------------- helpers
# These helpers are the bridge between Python and the running test environment.
# They run commands, read packet counters, and check whether XDP is attached.
def sh(cmd, timeout=15):
    """Run a shell command, return stdout."""
    # Python sends a command to the test environment and collects its output.
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout).stdout             #runs shell command and returns its output
    except Exception:
        return ""


def bpf_path():
    # Find the bpftool executable used to load/read the eBPF program.
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1'").strip()
    return out or "bpftool"


def read_nic_pkts():
    # Read packets received by the network card, before XDP filtering.
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'cat /proc/net/dev | grep eth0 | awk \"{{print \\$3}}\"'").strip()
    return int(out) if out.isdigit() else None


def read_app_pkts():
    # Read packets that reached the normal network stack, after XDP filtering.
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'grep \"^Ip:\" /proc/net/snmp | tail -1 | awk \"{{print \\$4}}\"'").strip()
    return int(out) if out.isdigit() else None


def read_xdp_stats():
    """Read stats_map: counters written by the real eBPF/XDP program."""
    # Ask the kernel for the counters produced by ddos_filter_kern.c.
    bpf = bpf_path()
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'{bpf} map dump name stats_map 2>/dev/null'")
    # Extract only the fields needed by the backend model.
    fields = ("udp_total", "udp_dropped", "udp_alerted",
              "syn_total", "syn_dropped", "syn_alerted")
    vals = {}
    # Add values from all CPUs because stats_map is a per-CPU map.
    for name, value in re.findall(r'"(' + "|".join(fields) + r')":\s*(\d+)', out):
        vals[name] = vals.get(name, 0) + int(value)
    return vals or None


def estimate_victim_resources(app_pps):
    """Estimate victim pressure from traffic that reaches the application.

    This makes the simulator show the resource cost that XDP is preventing.
    It is deliberately labelled as a model, because host-kernel packet work is
    not fully charged to the victim container by Docker.
    """
    app_pps = max(app_pps or 0, 0)
    cpu_pct = round(min(100.0, 2.0 + app_pps / 5000.0), 1)
    used_mb = round(32.0 + min(512.0, app_pps / 5000.0), 1)
    total_mb = 512.0
    return {
        "cpu_pct": cpu_pct,
        "memory": {
            "used_pct": round(100.0 * used_mb / total_mb, 1),
            "used_mb": used_mb,
            "total_mb": total_mb,
        },
        "source": "victim-load-model",
    }


def read_gpu():
    """Read NVIDIA GPU usage when nvidia-smi is available; otherwise report N/A."""
    out = sh("nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total "
             "--format=csv,noheader,nounits").strip()
    rows = []
    try:
        for line in out.splitlines():
            values = [float(value.strip()) for value in line.split(",")]
            if len(values) == 3:
                rows.append(values)
    except ValueError:
        rows = []
    if not rows:
        return {"available": False}
    return {
        "available": True,
        "util_pct": round(sum(row[0] for row in rows) / len(rows), 1),
        "memory_used_mb": round(sum(row[1] for row in rows), 1),
        "memory_total_mb": round(sum(row[2] for row in rows), 1),
    }


UDP_THRESHOLD = 800
SYN_THRESHOLD = 200


def build_model(xdp, prev_xdp, dt, attached):
    """Run the rate-limiter model on the server side, using real XDP counters.

    The kernel performs the real drop. This function only reproduces the
    decision for the dashboard using the counters exported through stats_map.
    """
    if not attached:
        # XDP is OFF, so there is no active kernel filter decision.
        return {"source": "docker+xdp", "attached": False}
    if not xdp:
        # The filter is attached but its counters are not available yet.
        return None
    if not prev_xdp:
        # Use the first reading as the starting point, not as new traffic.
        prev_xdp = xdp

    def delta(name):
        # Counters are cumulative; subtract the previous reading to get this
        # second's traffic.
        return max(xdp.get(name, 0) - prev_xdp.get(name, 0), 0)

    def entry(prefix, threshold):
        # Build the displayed result for one protocol: UDP or SYN.
        seen = delta(f"{prefix}_total")
        dropped = delta(f"{prefix}_dropped")
        rate = int(round(seen / dt))
        return {
            "rate": rate,
            "threshold": threshold,
            "seen": seen,
            "dropped": dropped,
            "state": "DROP" if rate > threshold else "PASS",
            "drop_pct": round(100.0 * dropped / seen, 1) if seen else 0.0,
        }

    # This object is placed in state and sent to the browser as JSON.
    return {
        "source": "docker+xdp",
        "attached": True,
        "window_s": round(dt, 3),
        "udp": entry("udp", UDP_THRESHOLD),
        "syn": entry("syn", SYN_THRESHOLD),
    }


def filter_is_on():
    out = sh(f"docker exec {VICTIM} bash -c "
             f"'ip link show eth0 | grep -q xdp && echo ON || echo OFF'").strip()
    return out == "ON"


PROJECT_DIR = None  # set in __main__


def prepare():
    """Prepare the target, copy the compiled filter, and start its service."""
    # Find the project root so the backend can locate the compiled .o file.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
    # Make sure the target services are running before the UI accepts requests.
    sh("docker start victim attacker benign")
    # The backend needs iptables and bpftool to control/read the filter.
    sh(f"docker exec {VICTIM} bash -c 'command -v iptables >/dev/null 2>&1 || "
       f"(apt-get update -qq && apt-get install -y -qq iptables) ; "
       f"ls /usr/lib/linux-tools/*/bpftool >/dev/null 2>&1 || "
       f"(apt-get update -qq && apt-get install -y -qq linux-tools-generic linux-tools-common)'")
    # Copy the compiled eBPF program that will later be attached to eth0.
    src = f"{root}/engine/ddos_filter_kern.o"
    if not os.path.exists(src):
        src = f"{root}/ebpf/ddos_filter_kern.o"
    # Copy the compiled filter into the target environment.
    sh(f"docker cp {src} {VICTIM}:/tmp/ddos_filter_kern.o")
    # Start the service that represents the application receiving traffic.
    sh(f"docker exec -d {VICTIM} bash -c 'pkill -9 iperf3 2>/dev/null; iperf3 -s -p 5201'")


def attach_filter():
    # Load the eBPF object once, pin it, and attach its XDP entry point.
    # First find the loader, then load/pin the program if it is not already loaded.
    bpf = bpf_path()
    # load (if needed) and attach
    sh(f"docker exec {VICTIM} bash -c '"
       f"if [ ! -e {PIN} ]; then rm -rf /sys/fs/bpf/ddos; "
       f"{bpf} prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos; fi; "
       f"ip link set dev eth0 xdp pinned {PIN}'")
    # Return the actual attachment state for the browser.
    return filter_is_on()


def detach_filter():
    # Stop XDP processing; packets can then continue normally.
    sh(f"docker exec {VICTIM} bash -c 'ip link set dev eth0 xdp off'")
    # Return the new state after detaching.
    return not filter_is_on()


FLOOD_FLAGS = {"udp": "-2", "syn": "-S"}


def flood_kinds(mode):
    return ("udp", "syn") if mode == "both" else (mode,)


def start_flood(mode="udp"):
    """Start four UDP workers, four SYN workers, or four of each."""
    # Remove old attack workers before starting the selected mode.
    sh(f"docker exec {ATTACKER} bash -c 'pkill -9 hping3 2>/dev/null; true'")
    for kind in flood_kinds(mode):
        # A mode uses four workers so the traffic rate is high enough to show
        # the difference between PASS and DROP.
        for _ in range(4):
            sh(f"docker exec -d {ATTACKER} hping3 {FLOOD_FLAGS[kind]} "
               f"-p 5201 --flood {VICTIM_IP}")


def stop_flood():
    # Stop all attack workers in the attacker process.
    sh(f"docker exec {ATTACKER} bash -c 'pkill -9 hping3 2>/dev/null; true'")


# ---------------------------------------------------------------- poller thread
# This is the measurement loop shown in the flowchart. It runs once per second:
# NIC counter -> application counter -> XDP stats -> backend model -> state.
def poll_loop():
    # Save the first counter readings. Later readings are compared with these.
    prev_nic = read_nic_pkts()
    prev_app = read_app_pkts()
    prev_xdp = read_xdp_stats()
    last_t = time.time()
    while True:
        # The dashboard is refreshed once per second.
        time.sleep(1)
        # Read the new packet and XDP counter values.
        now = read_nic_pkts()
        app = read_app_pkts()
        xdp = read_xdp_stats()
        t = time.time()
        dt = max(t - last_t, 0.001)
        # Convert cumulative NIC/application counters into packets per second.
        if now is not None and prev_nic is not None:
            nic_pps = int((now - prev_nic) / dt)
        else:
            nic_pps = 0
        if app is not None and prev_app is not None:
            app_pps = max(int((app - prev_app) / dt), 0)
        else:
            app_pps = 0

        # Check whether packets are currently passing through XDP.
        on = filter_is_on()
        # Read resource usage for the live resource cards.
        resources = estimate_victim_resources(app_pps)
        resources["gpu"] = read_gpu()
        # The Python model reads real kernel counters and prepares the dashboard
        # verdict. The C/XDP program has already made the actual packet decision.
        model = build_model(xdp, prev_xdp, dt, on)
        if xdp is not None:
            prev_xdp = xdp
        # Make the current readings the previous readings for the next loop.
        prev_nic, prev_app, last_t = now, app, t

        drop = 0.0
        if on and nic_pps > 0:
            drop = round(100.0 * max(nic_pps - app_pps, 0) / nic_pps, 1)

        # Publish the new values for the browser and chart.
        with lock:
            state["filter_on"] = on
            state["nic_pps"] = nic_pps
            state["app_pps"] = app_pps
            state["drop_pct"] = drop
            state["model"] = model
            state["resources"] = resources
            state["history"].append({"t": time.strftime("%H:%M:%S"),
                                     "nic": nic_pps, "app": app_pps})
            if len(state["history"]) > HISTORY:
                state["history"].pop(0)


# ---------------------------------------------------------------- flood thread
# This worker keeps the selected UDP/SYN/both attack alive for two minutes and
# replaces workers if one exits early.
def flood_loop(mode, gen):
    """Keeps the selected UDP/SYN/both flood running for FLOOD_SECONDS."""
    def still_current():
        with lock:
            return (state["flood_gen"] == gen and state["flood_running"]
                    and state["flood_mode"] == mode)

    # Decide how many UDP and SYN workers this mode should maintain.
    targets = {"udp": 4, "syn": 4} if mode == "both" else {mode: 4}
    end = time.time() + FLOOD_SECONDS
    with flood_lock:
        if not still_current():
            return
        # Start the selected attack only if this is still the latest request.
        start_flood(mode)
    while time.time() < end:
        with lock:
            if (state["flood_gen"] != gen or not state["flood_running"]
                    or state["flood_mode"] != mode):
                return
            # Update the countdown shown in the browser.
            state["flood_remaining"] = int(end - time.time())
        time.sleep(1)
        with flood_lock:
            if not still_current():
                return
            # Keep the right number of each worker type alive.
            out = sh(f"docker exec {ATTACKER} bash -c 'pgrep -af hping3 || true'")
            counts = {"udp": 0, "syn": 0}
            for line in out.splitlines():
                if "hping3 " not in line:
                    continue
                if " -2 " in line:
                    counts["udp"] += 1
                elif " -S " in line:
                    counts["syn"] += 1
            for kind, target in targets.items():
                # Restart only the missing type: UDP or SYN.
                for _ in range(max(target - counts.get(kind, 0), 0)):
                    sh(f"docker exec -d {ATTACKER} hping3 {FLOOD_FLAGS[kind]} "
                       f"-p 5201 --flood {VICTIM_IP}")
    with flood_lock:
        with lock:
            if state["flood_gen"] != gen:
                return
            # The two-minute attack ended naturally, so reset its state.
            state["flood_running"] = False
            state["flood_mode"] = None
            state["flood_remaining"] = 0
            state["flood_gen"] += 1
        stop_flood()


# ---------------------------------------------------------------- normal traffic
# This worker represents a legitimate user. Its traffic should remain below
# the limit and should pass when the filter is ON.
def normal_loop():
    """Runs a legitimate user's traffic (iperf3 from benign) in a loop and
    reports the packet loss. Normal traffic should NOT be dropped."""
    while True:
        with lock:
            if not state["normal_running"]:
                break
        # Send a small legitimate stream and read its JSON result.
        out = sh(f"docker exec benign iperf3 -c {VICTIM_IP} -p 5201 -u -b 3M "
                 f"-t 4 --json", timeout=20)
        try:
            j = json.loads(out)
            s = j["end"]["sum"]
            loss = round(s.get("lost_percent", 0.0), 1)
            mbps = s.get("bits_per_second", 0) / 1e6
            # Save the normal user's speed and packet loss for the page.
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


# ---------------------------------------------------------------- HTTP page
# PAGE is the frontend. It is embedded here, so no separate web frontend file
# is needed for this simulator.
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
 .inline-code{background:#1e293b;padding:1px 5px;border-radius:4px;font-family:monospace}
 .controls{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
 button{font-size:15px;font-weight:600;border:0;border-radius:10px;padding:12px 22px;cursor:pointer;color:#fff}
 .start{background:#2563eb}.syn{background:#b45309}.both{background:#0e7490}.stop{background:#475569}
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

<div class="row">
  <div class="card"><div class="label">Packets hitting NIC</div><div class="value nic" id="nic">--</div><div class="label">per second (before XDP)</div></div>
  <div class="card"><div class="label">Packets reaching app</div><div class="value app" id="app">--</div><div class="label">per second (after XDP)</div></div>
  <div class="card"><div class="label">Drop rate</div><div class="value drop" id="drop">--</div><div class="label">dropped at the NIC</div></div>
  <div class="card"><div class="label">Normal traffic (legit)</div><div class="value" id="normal" style="font-size:22px">idle</div><div class="label">must NOT be dropped</div></div>
</div>

<div class="controls">
  <button class="start" id="udpBtn" onclick="startFlood('udp')">Start UDP Flood</button>
  <button class="syn" id="synBtn" onclick="startFlood('syn')">Start SYN Flood</button>
  <button class="both" id="bothBtn" onclick="startFlood('both')">Start Both Floods</button>
  <button class="stop" id="stopBtn" onclick="stopFlood()" disabled>Stop Flood</button>
  <button class="tog" id="filterBtn" onclick="toggleFilter()">Filter: OFF</button>
  <button class="normal" id="normalBtn" onclick="toggleNormal()">Start Normal Traffic</button>
</div>
<div class="status">Flood: <span id="floodState">idle</span> &nbsp;|&nbsp; Countdown: <span id="cd">--</span>s &nbsp;|&nbsp; Filter: <span id="fpill" class="pill off">OFF</span></div>

<h2 style="font-size:15px;margin:22px 0 0">Backend rate-limiter model — real XDP counters</h2>
<div class="row">
  <div class="card"><div class="label">UDP rate seen by XDP</div><div class="value nic" id="udpRate">--</div><div class="label" id="udpMeta">limit 800 pkt/s</div></div>
  <div class="card"><div class="label">UDP verdict (backend)</div><div class="value" id="udpState">--</div><div class="label">PASS = forward, DROP = discard</div></div>
  <div class="card"><div class="label">SYN rate seen by XDP</div><div class="value nic" id="synRate">--</div><div class="label" id="synMeta">limit 200 /s</div></div>
  <div class="card"><div class="label">SYN verdict (backend)</div><div class="value" id="synState">--</div><div class="label">PASS = forward, DROP = discard</div></div>
</div>
<div class="status">Window: <span id="modelWin">--</span>s</div>

<h2 style="font-size:15px;margin:22px 0 0">Resource utilization</h2>
<div class="row">
  <div class="card"><div class="label">CPU</div><div class="value nic" id="cpuUse">--</div><div class="label">victim load model</div></div>
  <div class="card"><div class="label">Memory</div><div class="value nic" id="memoryUse">--</div><div class="label" id="memoryMeta">victim load model</div></div>
  <div class="card"><div class="label">GPU</div><div class="value nic" id="gpuUse">N/A</div><div class="label" id="gpuMeta">nvidia-smi unavailable</div></div>
</div>

<h2 style="font-size:15px;margin:22px 0 0">Live traffic (packets/sec)</h2>
<canvas id="chart" height="170"></canvas>
<div class="legend"><span class="dot" style="background:#60a5fa"></span>NIC (before XDP)
 &nbsp;&nbsp;<span class="dot" style="background:#34d399"></span>App (after XDP)</div>

<script>
let hist=[];
function nf(n){return (n||0).toLocaleString();}
// Ask the Python backend for the latest shared state.
async function getState(){const r=await fetch('/api/state');return r.json();}
// Browser button -> backend HTTP request. The browser only requests actions;
// Python performs them and returns the resulting state.
// These functions do not generate packets themselves.
async function toggleFilter(){const s=await getState();await fetch('/api/filter/'+(s.filter_on?'off':'on'),{method:'POST'});refresh();}
async function startFlood(mode){await fetch('/api/flood/'+mode,{method:'POST'});refresh();}
async function stopFlood(){await fetch('/api/flood/stop',{method:'POST'});refresh();}
async function toggleNormal(){const s=await getState();await fetch('/api/normal/'+(s.normal_running?'stop':'start'),{method:'POST'});refresh();}

function draw(){
 // Draw the NIC and application rates calculated by the backend.
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
  // Poll the Python backend every second and redraw the values it computed.
  const s=await getState();
  document.getElementById('nic').textContent=nf(s.nic_pps);
  document.getElementById('app').textContent=nf(s.app_pps);
  document.getElementById('drop').textContent=s.filter_on?s.drop_pct+'%':'OFF';
  document.getElementById('filterBtn').textContent='Filter: '+(s.filter_on?'ON':'OFF');
  document.getElementById('filterBtn').className='tog'+(s.filter_on?' on':'');
  document.getElementById('fpill').textContent=s.filter_on?'ON':'OFF';
  document.getElementById('fpill').className='pill '+(s.filter_on?'on':'off');
  const mode=s.flood_mode||'';
  document.getElementById('floodState').textContent=s.flood_running?('RUNNING ('+mode.toUpperCase()+')'):'idle';
  document.getElementById('cd').textContent=s.flood_running?s.flood_remaining:'--';
  const ub=document.getElementById('udpBtn'), sb=document.getElementById('synBtn');
  const bb=document.getElementById('bothBtn'), st=document.getElementById('stopBtn');
  ub.disabled=s.flood_running; sb.disabled=s.flood_running;
  bb.disabled=s.flood_running; st.disabled=!s.flood_running;
  ub.textContent=(s.flood_running&&mode==='udp')?'UDP Flood (running)':'Start UDP Flood';
  sb.textContent=(s.flood_running&&mode==='syn')?'SYN Flood (running)':'Start SYN Flood';
  bb.textContent=(s.flood_running&&mode==='both')?'Both Floods (running)':'Start Both Floods';
  const nb=document.getElementById('normalBtn');
  nb.textContent=s.normal_running?'Stop Normal Traffic':'Start Normal Traffic';
  nb.className='normal'+(s.normal_running?' on':'');
  const nel=document.getElementById('normal');
  nel.textContent=s.normal_status;
  if(s.normal_running && s.normal_loss!==null){nel.style.color=s.normal_loss>5?'#f87171':'#34d399';}
  else{nel.style.color='#e2e8f0';}
  const m=s.model||null;
  // Display the backend model result; do not recalculate it in the browser.
  function mset(rateId,stateId,metaId,data,meta){
    const re=document.getElementById(rateId),se=document.getElementById(stateId),me=document.getElementById(metaId);
    if(!m||!m.attached||!data){re.textContent='--';se.textContent=(m&&!m.attached)?'OFF':'no data';se.style.color='#94a3b8';me.textContent=meta;return;}
    re.textContent=nf(data.rate)+' pps';
    se.textContent=data.state;
    se.style.color=data.state==='DROP'?'#f87171':'#34d399';
    me.textContent=meta+' · dropped '+nf(data.dropped)+' ('+data.drop_pct+'%)';
  }
  mset('udpRate','udpState','udpMeta',m&&m.udp,'limit 800 pkt/s');
  mset('synRate','synState','synMeta',m&&m.syn,'limit 200 /s');
  document.getElementById('modelWin').textContent=m&&m.window_s?m.window_s:'--';
  // Resource cards are also backend values; GPU is N/A when no NVIDIA GPU exists.
  const r=s.resources||{}, mem=r.memory||{}, gpu=r.gpu||{};
  const pct=v=>(v===null||v===undefined)?'--':v+'%';
  document.getElementById('cpuUse').textContent=pct(r.cpu_pct);
  document.getElementById('memoryUse').textContent=pct(mem.used_pct);
  document.getElementById('memoryMeta').textContent=mem.used_mb===null||mem.used_mb===undefined?'victim load model':'model: '+nf(mem.used_mb)+' / '+nf(mem.total_mb)+' MB';
  document.getElementById('gpuUse').textContent=gpu.available?pct(gpu.util_pct):'N/A';
  document.getElementById('gpuMeta').textContent=gpu.available?'GPU utilization':'nvidia-smi unavailable';
  hist=s.history||[];draw();
 }catch(e){}
}
setInterval(refresh,1000);refresh();
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    # This handler is the browser/backend connection: GET reads state and
    # POST starts/stops floods, normal traffic, and the XDP filter.
    def _send(self, body, ctype="text/html"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # Browser GET requests read the current state or request the page.
        if self.path == "/api/state":
            with lock:
                data = dict(state)
            self._send(json.dumps(data), "application/json")
        elif self.path == "/api/model":
            with lock:
                data = state["model"]
            self._send(json.dumps(data), "application/json")
        else:
            self._send(PAGE)

    def do_POST(self):
        # Browser POST requests perform actions: filter, flood, or normal traffic.
        if self.path.startswith("/api/filter/"):
            want = self.path.rsplit("/", 1)[-1]
            if want == "on":
                attach_filter()
            else:
                detach_filter()
            self._send(json.dumps({"ok": True}), "application/json")
        elif self.path.startswith("/api/flood/"):
            want = self.path.rsplit("/", 1)[-1]
            if want == "stop":
                # Invalidate the current flood worker before stopping it.
                with flood_lock:
                    with lock:
                        state["flood_running"] = False
                        state["flood_mode"] = None
                        state["flood_gen"] += 1
                        state["flood_remaining"] = 0
                    stop_flood()
                ok = True
            elif want in ("udp", "syn", "both"):
                # Allow only one selected flood mode at a time.
                with lock:
                    ok = not state["flood_running"]
                    if ok:
                        state["flood_running"] = True
                        state["flood_mode"] = want
                        state["flood_gen"] += 1
                        gen = state["flood_gen"]
                if ok:
                    threading.Thread(target=flood_loop, args=(want, gen),
                                     daemon=True).start()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self._send(json.dumps({"ok": ok}), "application/json")
        elif self.path.startswith("/api/normal/"):
            want = self.path.rsplit("/", 1)[-1]
            with lock:
                if want == "start" and not state["normal_running"]:
                    # Start the legitimate-traffic worker in the background.
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
    # Startup order: prepare the target, start measurements, then serve browser
    # requests on port 8090.
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
