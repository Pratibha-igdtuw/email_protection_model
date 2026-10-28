/* FORENSIQ UI behaviour: mobile sidebar, risk-gauge animation, and the
   "analyzing" overlay. Plain JS, no dependencies, safe if elements are absent. */
(function () {
  'use strict';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Mobile sidebar
  var tg = document.getElementById('sideToggle'), bd = document.getElementById('sideBackdrop');
  if (tg) tg.addEventListener('click', function () { document.body.classList.toggle('side-open'); });
  if (bd) bd.addEventListener('click', function () { document.body.classList.remove('side-open'); });

  // Risk gauge: sweep the ring and count the number up
  document.querySelectorAll('.score-circle[data-score]').forEach(function (ring) {
    var target = Math.max(0, Math.min(100, parseFloat(ring.getAttribute('data-score')) || 0));
    var num = ring.parentNode.querySelector('.score-num');
    if (reduce) { ring.style.setProperty('--pct', target); return; }
    var t0 = null, dur = 1400;
    function tick(ts) {
      if (t0 === null) t0 = ts;
      var p = Math.min((ts - t0) / dur, 1), e = 1 - Math.pow(1 - p, 3), v = target * e;
      ring.style.setProperty('--pct', v);
      if (num) num.textContent = Math.round(v);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });

  // Count-up for any [data-countup] number
  document.querySelectorAll('[data-countup]').forEach(function (el) {
    var target = parseFloat(el.getAttribute('data-countup')); if (isNaN(target) || reduce) return;
    var t0 = null;
    function tick(ts) { if (t0 === null) t0 = ts; var p = Math.min((ts - t0) / 900, 1); el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(tick); }
    requestAnimationFrame(tick);
  });

  // Analyzing overlay -- shown while /analyze (about 4s) runs. Steps advance on a
  // fixed schedule: a visual cue only, not live backend progress.
  var STEPS = ['Parsing headers & relay hops', 'SPF / DKIM / DMARC check', 'WHOIS & domain age',
               'GeoIP & blacklist lookup', 'AI phishing classifier', 'Building risk score & evidence chain'];
  var overlay = null;
  function build() {
    overlay = document.createElement('div');
    overlay.className = 'mf-overlay'; overlay.setAttribute('role', 'status'); overlay.setAttribute('aria-live', 'polite');
    overlay.innerHTML = '<div class="mf-box"><div class="mf-fox"><i class="fa-solid fa-shield-halved"></i></div><h2>Analyzing your email…</h2>' +
      '<div class="mf-sub">All checks run in parallel — usually under 5 seconds</div>' +
      '<div class="mf-scan"><div class="ln" style="width:60%"></div><div class="ln"></div><div class="ln f" style="width:85%"></div>' +
      '<div class="ln" style="width:70%"></div><div class="ln f" style="width:50%"></div><div class="ln" style="width:90%"></div><div class="beam"></div></div>' +
      '<div class="mf-steps">' + STEPS.map(function (s) { return '<div class="mf-step"><span class="d"></span>' + s + '</div>'; }).join('') + '</div>' +
      '<div class="mf-pg"><i></i></div><div class="mf-timer">0.0s</div></div>';
    document.body.appendChild(overlay);
  }
  var timers = [];
  function showOverlay() {
    if (!overlay) build();
    var steps = overlay.querySelectorAll('.mf-step'), bar = overlay.querySelector('.mf-pg i'), tm = overlay.querySelector('.mf-timer');
    steps.forEach(function (s) { s.className = 'mf-step'; }); bar.style.width = '0';
    overlay.classList.add('on');
    var i = 0, t0 = Date.now();
    function step() {
      if (i > 0 && steps[i - 1]) steps[i - 1].className = 'mf-step ok';
      if (i < steps.length) { steps[i].className = 'mf-step run'; bar.style.width = ((i + 1) / steps.length * 100 * 0.92) + '%'; i++; timers.push(setTimeout(step, i === 3 ? 900 : 560)); }
    }
    timers.push(setTimeout(step, 200));
    timers.push(setInterval(function () { tm.textContent = ((Date.now() - t0) / 1000).toFixed(1) + 's'; }, 100));
  }
  function hideOverlay() { timers.forEach(function (t) { clearTimeout(t); clearInterval(t); }); timers = []; if (overlay) overlay.classList.remove('on'); }
  window.addEventListener('pageshow', hideOverlay); // back/forward cache

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || !f.getAttribute) return;
    var action = f.getAttribute('action') || '';
    if (/\/analyze(\/|$|\?)/.test(action) && f.method && f.method.toLowerCase() === 'post' && !e.defaultPrevented) showOverlay();
  });
})();
