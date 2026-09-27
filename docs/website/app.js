/* ==========================================================================
   eBPF/XDP DDoS Mitigation Project — website behavior
   ========================================================================== */
(function () {
  'use strict';

  /* -------------------------------------------------------------------------
   * 1. Sidebar + reading progress + back-to-top
   * ----------------------------------------------------------------------- */
  var sidebar = document.getElementById('sidebar');
  var burger = document.getElementById('burger');
  var progressEl = document.getElementById('progress');
  var scrollTopBtn = document.getElementById('scrollTop');

  burger.addEventListener('click', function () {
    sidebar.classList.toggle('open');
  });

  document.addEventListener('click', function (e) {
    if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== burger) {
      sidebar.classList.remove('open');
    }
  });

  function onScroll() {
    var h = document.documentElement;
    var scrolled = h.scrollTop / (h.scrollHeight - h.clientHeight) * 100;
    progressEl.style.width = scrolled + '%';
    if (window.scrollY > 500) scrollTopBtn.classList.add('show');
    else scrollTopBtn.classList.remove('show');
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  scrollTopBtn.addEventListener('click', function () {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  /* -------------------------------------------------------------------------
   * 2. Scroll-spy: highlight current section in the sidebar
   * ----------------------------------------------------------------------- */
  var navLinks = Array.prototype.slice.call(document.querySelectorAll('.sidebar nav a'));
  var sections = navLinks.map(function (a) {
    var id = a.getAttribute('href').slice(1);
    return { id: id, el: document.getElementById(id), link: a };
  });

  function spy() {
    var pos = window.scrollY + 120;
    var current = null;
    for (var i = 0; i < sections.length; i++) {
      var s = sections[i];
      if (s.el && s.el.offsetTop <= pos) current = s;
    }
    navLinks.forEach(function (a) { a.classList.remove('active'); });
    if (current) current.link.classList.add('active');
  }
  window.addEventListener('scroll', spy, { passive: true });
  spy();

  /* -------------------------------------------------------------------------
   * 3. Simple syntax highlighting for <pre><code data-lang="...">
   * ----------------------------------------------------------------------- */
  var langs = {
    c: function (src) {
      src = src.replace(/\/\/[^\n]*/g, '<span class="tok-c">$&</span>');
      src = src.replace(/\/\*[\s\S]*?\*\//g, '<span class="tok-c">$&</span>');
      src = src.replace(/#[^\n]*/g, '<span class="tok-p">$&</span>');
      src = src.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="tok-s">$1</span>');
      src = src.replace(/\b(\d+(?:ULL|UL|L)?|0x[0-9a-fA-F]+)\b/g, '<span class="tok-n">$1</span>');
      src = src.replace(/\b(SEC|XDP_PASS|XDP_DROP|XDP_TX|XDP_REDIRECT|BPF_ANY|ETH_P_IP|IPPROTO_UDP|IPPROTO_TCP)\b/g, '<span class="tok-k">$1</span>');
      src = src.replace(/\b(__u32|__u64|__uint|__type|struct|void|int|char|long|return|if|else|for|while|static|unsigned|const)\b/g, '<span class="tok-t">$1</span>');
      return src;
    },
    python: function (src) {
      src = src.replace(/#[^\n]*/g, '<span class="tok-c">$&</span>');
      src = src.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, '<span class="tok-s">$1</span>');
      src = src.replace(/\b(def|return|import|from|if|elif|else|for|while|in|and|or|not|continue|break|with|open|class|lambda|None|True|False|print)\b/g, '<span class="tok-k">$1</span>');
      return src;
    },
    bash: function (src) {
      src = src.replace(/#[^\n]*/g, '<span class="tok-c">$&</span>');
      src = src.replace(/("[^"]*"|'[^']*')/g, '<span class="tok-s">$1</span>');
      src = src.replace(/\b(sudo|docker|make|ip|sleep|pkill|rm|ls|bash|xdp|prog|map|loadall|pinned|off|cp|exec)\b/g, '<span class="tok-k">$1</span>');
      return src;
    },
    makefile: function (src) {
      src = src.replace(/#[^\n]*/g, '<span class="tok-c">$&</span>');
      src = src.replace(/^[A-Z_]+ *\?*=.*$/gm, '<span class="tok-p">$&</span>');
      src = src.replace(/\b(all|clean)\b/g, '<span class="tok-k">$1</span>');
      return src;
    }
  };

  var preBlocks = document.querySelectorAll('pre code[data-lang]');
  Array.prototype.forEach.call(preBlocks, function (code) {
    var fn = langs[code.getAttribute('data-lang')];
    var raw = code.textContent;
    if (fn) {
      code.innerHTML = fn(raw);
    }
  });

  /* -------------------------------------------------------------------------
   * 4. Animated result bars (trigger once when visible)
   * ----------------------------------------------------------------------- */
  var bars = document.querySelectorAll('.bar-fill[data-w]');
  var barsDone = false;
  function fillBars() {
    if (barsDone) return;
    if (document.getElementById('results') && window.scrollY + window.innerHeight > document.getElementById('results').offsetTop) {
      barsDone = true;
      Array.prototype.forEach.call(bars, function (b) {
        b.style.width = b.getAttribute('data-w') + '%';
      });
    }
  }
  window.addEventListener('scroll', fillBars, { passive: true });
  fillBars();

  /* -------------------------------------------------------------------------
   * 5. Interactive demo: the sliding-window rate limiter
   * ----------------------------------------------------------------------- */
  var canvas = document.getElementById('demoCanvas');
  var btnStart = document.getElementById('btnStart');
  var btnStop = document.getElementById('btnStop');
  var dCount = document.getElementById('dCount');
  var dState = document.getElementById('dState');
  var dDropped = document.getElementById('dDropped');

  var ctx = canvas && canvas.getContext('2d');
  if (!canvas || !ctx || !dCount) return;

  var running = false;      // is the flood active?
  var counter = 0;          // packets this window
  var dropped = 0;          // packets dropped by XDP
  var packets = [];         // on-screen packets (visual only)
  var THRESHOLD = 800;      // UDP limit (packets/second)
  var RATE = 1600;          // attacker sends this many packets/second
  var WIN_MS = 1000;        // 1-second sliding window
  var simMs = 0;            // simulated time since start
  var windowStart = 0;      // simulated time when current window began
  var nextPacketAt = 0;     // simulated time of the next packet arrival
  var lastFrame = null;

  function updateText() {
    dCount.textContent = counter;
    dDropped.textContent = dropped;
    var flooding = counter > THRESHOLD;
    dState.textContent = flooding ? 'DROP (flooding!)' : 'PASS (normal)';
    dState.style.color = flooding ? 'var(--danger)' : 'var(--accent-2)';
  }

  function onPacket() {
    /* sliding-window logic, exactly like the kernel program:
       pass until the sender exceeds 800 in one second, then drop. */
    if (counter >= THRESHOLD) {
      dropped++;                       // XDP_DROP: thrown away at the NIC
    } else {
      counter++;
    }
    packets.push({ x: -6, y: 6 });
    updateText();
  }

  function loop(now) {
    if (!running) return;
    if (!lastFrame) lastFrame = now;
    var dt = Math.min(now - lastFrame, 100);   // clamp huge gaps
    lastFrame = now;
    simMs += dt;

    /* when a fresh second starts, reset the counter (like the real program) */
    if (simMs - windowStart >= WIN_MS) {
      counter = 0;
      windowStart = simMs;
    }

    /* generate packets at the attacker's rate, capped so a slow tab
       doesn't burst thousands of packets in one frame */
    var interval = 1000 / RATE;
    var guard = 0;
    while (simMs >= nextPacketAt && guard < 5) {
      onPacket();
      nextPacketAt += interval;
      guard++;
    }

    /* move the on-screen packets and keep the scene tidy */
    for (var i = 0; i < packets.length; i++) packets[i].x += 3;
    if (packets.length > 5) packets.shift();

    updateText();
    draw();
    requestAnimationFrame(loop);
  }

  function draw() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    /* threshold line */
    var thX = (THRESHOLD / 1600) * canvas.width * 0.9 + 20;
    ctx.strokeStyle = 'rgba(251,191,36,0.7)';
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    ctx.moveTo(thX, 0);
    ctx.lineTo(thX, canvas.height);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(251,191,36,0.9)';
    ctx.font = '11px monospace';
    ctx.fillText('limit 800', thX + 6, 14);

    /* packets */
    for (var i = 0; i < packets.length; i++) {
      var p = packets[i];
      var col = counter > THRESHOLD ? 'rgba(248,113,113,0.9)' : 'rgba(52,211,153,0.9)';
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.arc(p.x, canvas.height / 2, 5, 0, Math.PI * 2);
      ctx.fill();
    }

    /* counter bar (portion of window used) */
    var w = canvas.width;
    var frac = Math.min(counter / (THRESHOLD * 2), 1);
    ctx.fillStyle = 'rgba(56,189,248,0.25)';
    ctx.fillRect(0, canvas.height - 14, w * frac, 8);
    ctx.strokeStyle = 'rgba(56,189,248,0.6)';
    ctx.strokeRect(0, canvas.height - 14, w, 8);
  }

  btnStart.addEventListener('click', function () {
    if (running) return;
    counter = 0; dropped = 0; packets = [];
    simMs = 0; windowStart = 0; nextPacketAt = 0; lastFrame = null;
    running = true;
    btnStart.disabled = true;
    btnStop.disabled = false;
    updateText();
    requestAnimationFrame(loop);
  });

  btnStop.addEventListener('click', function () {
    running = false;
    btnStart.disabled = false;
    btnStop.disabled = true;
  });

  if (canvas) {
    function sizeCanvas() {
      canvas.width = Math.max(320, canvas.parentElement.clientWidth - 2);
      canvas.height = 150;
      draw();
    }
    window.addEventListener('resize', sizeCanvas);
    sizeCanvas();
  }
})();