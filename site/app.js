(function () {
  "use strict";

  var FLOOD_SECONDS = 120;
  var HISTORY = 60;
  var RATES = {
    udp: 220000,
    syn: 200000,
    both: 390000
  };

  var state = {
    filterOn: false,
    running: false,
    mode: null,
    remaining: 0,
    nic: 0,
    app: 0,
    drop: 0,
    udp: 0,
    syn: 0,
    cpu: 2,
    mem: 32,
    history: []
  };

  var els = {
    udpBtn: document.getElementById("udpBtn"),
    synBtn: document.getElementById("synBtn"),
    bothBtn: document.getElementById("bothBtn"),
    stopBtn: document.getElementById("stopBtn"),
    filterBtn: document.getElementById("filterBtn"),
    floodState: document.getElementById("floodState"),
    countdown: document.getElementById("countdown"),
    filterPill: document.getElementById("filterPill"),
    nicValue: document.getElementById("nicValue"),
    appValue: document.getElementById("appValue"),
    dropValue: document.getElementById("dropValue"),
    udpRate: document.getElementById("udpRate"),
    udpState: document.getElementById("udpState"),
    udpHint: document.getElementById("udpHint"),
    synRate: document.getElementById("synRate"),
    synState: document.getElementById("synState"),
    synHint: document.getElementById("synHint"),
    cpuValue: document.getElementById("cpuValue"),
    memValue: document.getElementById("memValue"),
    gpuValue: document.getElementById("gpuValue"),
    cpuHint: document.getElementById("cpuHint"),
    memHint: document.getElementById("memHint"),
    chart: document.getElementById("chart")
  };

  function nf(value) {
    return Math.round(value || 0).toLocaleString();
  }

  function compact(value) {
    if (value >= 1000000) return (value / 1000000).toFixed(1) + "M";
    if (value >= 1000) return Math.round(value / 1000) + "k";
    return String(Math.round(value));
  }

  function jitter(scale) {
    return scale * (0.92 + Math.random() * 0.16);
  }

  function sample() {
    var nic;
    var udp;
    var syn;

    if (state.running) {
      var base = jitter(RATES[state.mode] || 0);
      if (state.mode === "udp") {
        udp = base;
        syn = 24 + Math.random() * 24;
      } else if (state.mode === "syn") {
        syn = base;
        udp = 24 + Math.random() * 24;
      } else {
        udp = base * 0.52;
        syn = base * 0.48;
      }
      nic = udp + syn;
    } else {
      nic = 360 + Math.random() * 340;
      udp = 260 + Math.random() * 230;
      syn = 8 + Math.random() * 14;
    }

    state.nic = Math.round(nic);
    state.udp = Math.round(udp);
    state.syn = Math.round(syn);

    if (state.filterOn && state.running) {
      state.app = Math.round(Math.min(nic, 420 + Math.random() * 360));
    } else {
      state.app = Math.round(nic);
    }

    state.drop = state.filterOn && state.running && nic > 0
      ? Math.round((1000 * (nic - state.app)) / nic) / 10
      : 0;

    state.cpu = Math.min(100, 2 + state.app / 5000);
    state.mem = 32 + Math.min(512, state.app / 5000);

    state.history.push({ nic: state.nic, app: state.app });
    if (state.history.length > HISTORY) {
      state.history.shift();
    }
  }

  function verdict(rate, limit) {
    return rate > limit ? "DROP" : "PASS";
  }

  function setVerdict(element, value) {
    element.textContent = value;
    if (value === "DROP") element.style.color = "var(--red)";
    else if (value === "PASS") element.style.color = "var(--green)";
    else element.style.color = "var(--muted)";
  }

  function render() {
    var running = state.running;
    var mode = state.mode;

    els.nicValue.textContent = nf(state.nic);
    els.appValue.textContent = nf(state.app);
    els.dropValue.textContent = state.drop.toFixed(1) + "%";

    els.udpRate.textContent = nf(state.udp) + " pps";
    els.synRate.textContent = nf(state.syn) + " pps";
    setVerdict(els.udpState, state.filterOn ? verdict(state.udp, 800) : "OFF");
    setVerdict(els.synState, state.filterOn ? verdict(state.syn, 200) : "OFF");
    els.udpHint.textContent = "limit 800 pkt/s";
    els.synHint.textContent = "limit 200 /s";

    els.cpuValue.textContent = state.cpu.toFixed(1) + "%";
    els.memValue.textContent = state.mem.toFixed(1) + " MB";
    els.gpuValue.textContent = "N/A";
    els.cpuHint.textContent = "victim load model";
    els.memHint.textContent = "of 512 MB model";

    els.floodState.textContent = running ? "RUNNING (" + mode.toUpperCase() + ")" : "idle";
    els.countdown.textContent = running ? state.remaining + "s" : "--";

    els.filterBtn.textContent = "Filter: " + (state.filterOn ? "ON" : "OFF");
    els.filterBtn.className = "action filter" + (state.filterOn ? " on" : "");
    els.filterPill.textContent = state.filterOn ? "ON" : "OFF";
    els.filterPill.className = "pill " + (state.filterOn ? "on" : "off");

    els.udpBtn.disabled = running;
    els.synBtn.disabled = running;
    els.bothBtn.disabled = running;
    els.stopBtn.disabled = !running;

    els.udpBtn.textContent = running && mode === "udp" ? "UDP flood running" : "Start UDP flood";
    els.synBtn.textContent = running && mode === "syn" ? "SYN flood running" : "Start SYN flood";
    els.bothBtn.textContent = running && mode === "both" ? "Both floods running" : "Start both floods";

    drawChart();
  }

  function tick() {
    if (state.running) {
      state.remaining -= 1;
      if (state.remaining <= 0) {
        state.running = false;
        state.mode = null;
        state.remaining = 0;
      }
    }
    sample();
    render();
  }

  function startFlood(mode) {
    if (state.running) return;
    state.running = true;
    state.mode = mode;
    state.remaining = FLOOD_SECONDS;
    sample();
    render();
  }

  function stopFlood() {
    state.running = false;
    state.mode = null;
    state.remaining = 0;
    sample();
    render();
  }

  function toggleFilter() {
    state.filterOn = !state.filterOn;
    sample();
    render();
  }

  function drawChart() {
    var canvas = els.chart;
    if (!canvas) return;

    var ratio = window.devicePixelRatio || 1;
    var width = canvas.clientWidth || 800;
    var height = 220;

    if (canvas.width !== Math.floor(width * ratio) || canvas.height !== Math.floor(height * ratio)) {
      canvas.width = Math.floor(width * ratio);
      canvas.height = Math.floor(height * ratio);
    }

    var ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);

    var pad = { left: 50, right: 12, top: 12, bottom: 24 };
    var plotW = Math.max(1, width - pad.left - pad.right);
    var plotH = Math.max(1, height - pad.top - pad.bottom);
    var max = 1000;

    state.history.forEach(function (point) {
      max = Math.max(max, point.nic, point.app);
    });
    max *= 1.12;

    ctx.font = "11px Segoe UI, Arial, sans-serif";
    ctx.fillStyle = "#6b7c96";
    ctx.strokeStyle = "#243653";
    ctx.lineWidth = 1;

    var i;
    for (i = 0; i <= 4; i += 1) {
      var y = pad.top + (plotH * i) / 4;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(width - pad.right, y);
      ctx.stroke();
      ctx.fillText(compact(max * (1 - i / 4)), 4, y + 4);
    }

    if (state.history.length < 2) return;

    function drawLine(key, color) {
      var denom = Math.max(1, state.history.length - 1);
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      state.history.forEach(function (point, index) {
        var x = pad.left + (plotW * index) / denom;
        var y = pad.top + plotH - (point[key] / max) * plotH;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    drawLine("nic", "#5aa9ff");
    drawLine("app", "#38d39f");
  }

  els.udpBtn.addEventListener("click", function () { startFlood("udp"); });
  els.synBtn.addEventListener("click", function () { startFlood("syn"); });
  els.bothBtn.addEventListener("click", function () { startFlood("both"); });
  els.stopBtn.addEventListener("click", stopFlood);
  els.filterBtn.addEventListener("click", toggleFilter);
  window.addEventListener("resize", drawChart);

  for (var i = 0; i < 24; i += 1) {
    var ambient = 380 + Math.random() * 240;
    state.history.push({ nic: Math.round(ambient), app: Math.round(ambient) });
  }

  sample();
  render();
  setInterval(tick, 1000);
}());
