/*
 * AI Bot Defender — Layer-1 browser fingerprint collector.
 *
 * A self-contained, dependency-free script embedded in honeypot pages. It reads
 * the JS-visible attribute surfaces an industry fingerprinter uses — canvas,
 * WebGL/WebGPU, AudioContext, fonts, screen/window geometry, navigator/UA-CH,
 * automation tells — plus behavioral biometrics (mouse/scroll/keystroke), and
 * POSTs one JSON payload to /__fpbeacon (same-origin; nginx routes it to the
 * fp-collector, which writes logdb.browser_fingerprints). crawler_graph then
 * joins these to the request/TLS/TCP layers by (client_ip[, client_port]) and
 * uses them as device-graph correlation keys + cross-layer consistency checks.
 *
 * Design rules:
 *   - Never throw into the page: every surface is wrapped; a failure on one
 *     surface still yields a partial fingerprint.
 *   - Fire-and-forget: a "load" beacon goes out after a short settle (so we get
 *     a fingerprint even with zero interaction), and a richer "unload" beacon
 *     with accumulated behavior is flushed via navigator.sendBeacon on pagehide.
 *   - Plain scrapers that don't run JS simply never beacon — and that ABSENCE
 *     (HTML fetched, no fingerprint) is itself a signal the server side reads.
 *
 * The payload schema below is the contract shared with proxy/fp-collector/app.py
 * and crawler_graph (ingest.enrich.join_browser_fingerprints) — keep them in sync.
 */
(function () {
  "use strict";

  var BEACON_PATH = "/__fpbeacon";
  var SETTLE_MS = 1200; // grab a fingerprint even if the visitor never interacts

  // --- cyrb53: a compact, fast, deterministic 53-bit string hash ------------
  // We hash the high-entropy surfaces (canvas/audio pixel buffers, font sets)
  // into stable hex digests client-side; SubtleCrypto is async/unavailable in
  // some contexts, and an exact device-keying hash only needs determinism.
  function cyrb53(str, seed) {
    var h1 = 0xdeadbeef ^ (seed || 0);
    var h2 = 0x41c6ce57 ^ (seed || 0);
    for (var i = 0, ch; i < str.length; i++) {
      ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    var n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
    return ("0000000000000" + n.toString(16)).slice(-14);
  }

  function safe(fn, dflt) {
    try { return fn(); } catch (e) { return dflt; }
  }

  // --- Canvas: GPU + driver + OS rasterization pipeline ---------------------
  function canvasFingerprint() {
    return safe(function () {
      var c = document.createElement("canvas");
      c.width = 280; c.height = 60;
      var ctx = c.getContext("2d");
      if (!ctx) return { hash: null, winding: null };
      // Winding tells apart fill-rule implementations.
      var winding = safe(function () {
        ctx.rect(0, 0, 10, 10); ctx.rect(2, 2, 6, 6);
        return ctx.isPointInPath(5, 5, "evenodd") === false;
      }, null);
      ctx.textBaseline = "alphabetic";
      ctx.fillStyle = "#f60"; ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069"; ctx.font = "11pt 'Arial'";
      ctx.fillText("AI-Bot-Defender 🐞 canary 0123", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)"; ctx.font = "18pt 'Arial'";
      ctx.fillText("Σµ®✂ Cwm fjord", 4, 45);
      // A second pass with a gradient + composite op exercises more of the pipe.
      var grad = ctx.createLinearGradient(0, 0, 280, 0);
      grad.addColorStop(0, "rgba(255,0,255,0.5)");
      grad.addColorStop(1, "rgba(0,255,255,0.5)");
      ctx.fillStyle = grad; ctx.globalCompositeOperation = "multiply";
      ctx.beginPath(); ctx.arc(50, 30, 28, 0, Math.PI * 2); ctx.fill();
      var data = c.toDataURL();
      return { hash: cyrb53(data), winding: winding };
    }, { hash: null, winding: null });
  }

  // --- WebGL: GPU vendor/renderer + params + shader-compile timing ----------
  function webglFingerprint() {
    return safe(function () {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return { hash: null, vendor: null, renderer: null, params: {}, shaderMs: null };
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      var params = {};
      var pnames = ["MAX_TEXTURE_SIZE", "MAX_VIEWPORT_DIMS", "MAX_VERTEX_ATTRIBS",
        "MAX_VERTEX_UNIFORM_VECTORS", "MAX_FRAGMENT_UNIFORM_VECTORS",
        "MAX_RENDERBUFFER_SIZE", "MAX_TEXTURE_IMAGE_UNITS", "ALIASED_LINE_WIDTH_RANGE",
        "ALIASED_POINT_SIZE_RANGE", "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "RED_BITS",
        "GREEN_BITS", "BLUE_BITS", "ALPHA_BITS", "DEPTH_BITS", "STENCIL_BITS"];
      for (var i = 0; i < pnames.length; i++) {
        params[pnames[i]] = safe(function () {
          var v = gl.getParameter(gl[pnames[i]]);
          return v && v.length !== undefined ? Array.prototype.slice.call(v) : v;
        }, null);
      }
      var exts = safe(function () { return (gl.getSupportedExtensions() || []).sort(); }, []);
      // Fragment-shader execution latency is characteristic of the GPU micro-arch.
      var shaderMs = safe(function () {
        var vs = gl.createShader(gl.VERTEX_SHADER);
        gl.shaderSource(vs, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}");
        gl.compileShader(vs);
        var fs = gl.createShader(gl.FRAGMENT_SHADER);
        gl.shaderSource(fs, "precision highp float;void main(){float a=0.0;" +
          "for(int i=0;i<128;i++){a+=sin(float(i))*cos(float(i));}" +
          "gl_FragColor=vec4(fract(a),0.0,0.0,1.0);}");
        gl.compileShader(fs);
        var prog = gl.createProgram();
        gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog);
        gl.useProgram(prog);
        var buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
        var loc = gl.getAttribLocation(prog, "p");
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
        var t0 = performance.now();
        for (var k = 0; k < 60; k++) { gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4); }
        gl.finish();
        return Math.round((performance.now() - t0) * 1000) / 1000;
      }, null);
      var basis = JSON.stringify({ v: vendor, r: renderer, p: params, e: exts });
      return {
        hash: cyrb53(basis),
        vendor: vendor || null,
        renderer: renderer || null,
        params: params,
        extensions: exts,
        shaderMs: shaderMs
      };
    }, { hash: null, vendor: null, renderer: null, params: {}, shaderMs: null });
  }

  // --- WebGPU (Chromium/modern): adapter features + limits ------------------
  function webgpuFingerprint(out, done) {
    if (!navigator.gpu || !navigator.gpu.requestAdapter) { done(null); return; }
    var settled = false;
    var finish = function (v) { if (!settled) { settled = true; done(v); } };
    setTimeout(function () { finish(null); }, 600); // never block the beacon
    safe(function () {
      navigator.gpu.requestAdapter().then(function (adapter) {
        if (!adapter) { finish(null); return; }
        var info = adapter.info || {};
        var feats = safe(function () { return Array.from(adapter.features || []).sort(); }, []);
        var limits = {};
        safe(function () {
          var L = adapter.limits || {};
          for (var key in L) { if (typeof L[key] === "number") limits[key] = L[key]; }
        });
        finish({
          vendor: info.vendor || null,
          architecture: info.architecture || null,
          device: info.device || null,
          description: info.description || null,
          features: feats,
          limits: limits
        });
      }, function () { finish(null); });
    }, finish.bind(null, null));
  }

  // --- AudioContext: floating-point output of a fixed oscillator graph ------
  function audioFingerprint(done) {
    safe(function () {
      var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OAC) { done({ hash: null, sample: null }); return; }
      var ctx = new OAC(1, 5000, 44100);
      var osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      // Pin every compressor param so output depends only on the audio stack.
      safe(function () { comp.threshold.value = -50; });
      safe(function () { comp.knee.value = 40; });
      safe(function () { comp.ratio.value = 12; });
      safe(function () { comp.attack.value = 0; });
      safe(function () { comp.release.value = 0.25; });
      osc.connect(comp); comp.connect(ctx.destination);
      osc.start(0);
      var settled = false;
      var finish = function (buf) {
        if (settled) return; settled = true;
        if (!buf) { done({ hash: null, sample: null }); return; }
        var ch = buf.getChannelData(0);
        var acc = 0, sample = 0;
        for (var i = 0; i < ch.length; i++) { acc += Math.abs(ch[i]); }
        sample = ch.length ? Math.round((acc / ch.length) * 1e7) / 1e7 : 0;
        // Hash a slice of the actual samples for a high-entropy stable digest.
        var slice = [];
        for (var j = 4500; j < 5000; j++) { slice.push(ch[j] ? ch[j].toFixed(7) : "0"); }
        done({ hash: cyrb53(slice.join(",")), sample: sample });
      };
      ctx.oncomplete = function (e) { finish(e.renderedBuffer); };
      ctx.startRendering();
      setTimeout(function () { finish(null); }, 500); // safety net
    }, function () { done({ hash: null, sample: null }); });
  }

  // --- Fonts: detect installed fonts via text-metric deltas -----------------
  function fontFingerprint() {
    return safe(function () {
      var base = ["monospace", "sans-serif", "serif"];
      var probe = ["Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria",
        "Comic Sans MS", "Consolas", "Courier", "Courier New", "Georgia", "Helvetica",
        "Helvetica Neue", "Impact", "Lucida Console", "Lucida Sans Unicode", "Menlo",
        "Monaco", "Palatino", "Segoe UI", "Tahoma", "Times", "Times New Roman",
        "Trebuchet MS", "Verdana", "Geneva", "Gill Sans", "Cantarell", "Ubuntu",
        "DejaVu Sans", "Liberation Sans", "Noto Sans", "Roboto", "Droid Sans",
        "Open Sans", "PingFang SC", "Microsoft YaHei", "MS Gothic", "Apple Color Emoji",
        "Segoe UI Emoji", "Noto Color Emoji"];
      var span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;top:-9999px;" +
        "font-size:72px;line-height:normal;visibility:hidden;";
      span.textContent = "mmmmmmmmmmlli WwQq 0123";
      document.body.appendChild(span);
      var baseSize = {};
      for (var b = 0; b < base.length; b++) {
        span.style.fontFamily = base[b];
        baseSize[base[b]] = { w: span.offsetWidth, h: span.offsetHeight };
      }
      var detected = [];
      for (var p = 0; p < probe.length; p++) {
        var found = false;
        for (var bb = 0; bb < base.length; bb++) {
          span.style.fontFamily = "'" + probe[p] + "'," + base[bb];
          if (span.offsetWidth !== baseSize[base[bb]].w ||
              span.offsetHeight !== baseSize[base[bb]].h) { found = true; break; }
        }
        if (found) detected.push(probe[p]);
      }
      document.body.removeChild(span);
      return { fonts: detected, hash: cyrb53(detected.join(",")) };
    }, { fonts: [], hash: null });
  }

  // --- Screen / window geometry --------------------------------------------
  function screenInfo() {
    return safe(function () {
      var s = window.screen || {};
      var outerW = window.outerWidth || 0, outerH = window.outerHeight || 0;
      var innerW = window.innerWidth || 0, innerH = window.innerHeight || 0;
      return {
        w: s.width || null, h: s.height || null,
        availW: s.availWidth || null, availH: s.availHeight || null,
        dpr: window.devicePixelRatio || null,
        colorDepth: s.colorDepth || null, pixelDepth: s.pixelDepth || null,
        innerW: innerW, innerH: innerH, outerW: outerW, outerH: outerH,
        // outer-minus-inner leaks toolbars / devtools / extension chrome.
        chromeW: outerW && innerW ? outerW - innerW : null,
        chromeH: outerH && innerH ? outerH - innerH : null,
        orientation: safe(function () { return s.orientation ? s.orientation.type : null; }, null)
      };
    }, {});
  }

  // --- Navigator / environment ---------------------------------------------
  function navigatorInfo() {
    return safe(function () {
      var n = navigator;
      return {
        ua: n.userAgent || null,
        platform: n.platform || null,
        language: n.language || null,
        languages: safe(function () { return n.languages ? Array.prototype.slice.call(n.languages) : []; }, []),
        hardwareConcurrency: n.hardwareConcurrency || null,
        deviceMemory: n.deviceMemory || null,
        maxTouchPoints: n.maxTouchPoints || 0,
        touch: ("ontouchstart" in window) || (n.maxTouchPoints > 0),
        vendor: n.vendor || null,
        cookieEnabled: n.cookieEnabled,
        pdfViewerEnabled: typeof n.pdfViewerEnabled === "boolean" ? n.pdfViewerEnabled : null,
        doNotTrack: n.doNotTrack || null,
        timezone: safe(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }, null),
        timezoneOffset: safe(function () { return new Date().getTimezoneOffset(); }, null),
        plugins: safe(function () { return n.plugins ? n.plugins.length : 0; }, 0),
        mimeTypes: safe(function () { return n.mimeTypes ? n.mimeTypes.length : 0; }, 0)
      };
    }, {});
  }

  // --- High-entropy UA Client Hints (async, best-effort) --------------------
  function uaClientHints(done) {
    if (!navigator.userAgentData || !navigator.userAgentData.getHighEntropyValues) {
      done(null); return;
    }
    var settled = false;
    var finish = function (v) { if (!settled) { settled = true; done(v); } };
    setTimeout(function () { finish(null); }, 400);
    safe(function () {
      navigator.userAgentData.getHighEntropyValues([
        "architecture", "bitness", "model", "platform", "platformVersion",
        "uaFullVersion", "fullVersionList", "wow64"
      ]).then(function (hv) {
        finish({
          brands: safe(function () { return navigator.userAgentData.brands; }, null),
          mobile: navigator.userAgentData.mobile,
          platform: hv.platform || null,
          platformVersion: hv.platformVersion || null,
          architecture: hv.architecture || null,
          bitness: hv.bitness || null,
          model: hv.model || null,
          uaFullVersion: hv.uaFullVersion || null,
          fullVersionList: hv.fullVersionList || null,
          wow64: hv.wow64
        });
      }, function () { finish(null); });
    }, finish.bind(null, null));
  }

  // --- Automation / headless tells -----------------------------------------
  function automationTells(webglRenderer) {
    var t = {};
    t.webdriver = safe(function () { return navigator.webdriver === true; }, false);
    // Chrome DevTools Protocol / Selenium injected globals.
    t.cdc = safe(function () {
      for (var k in window) { if (/^(cdc_|\$cdc_|__webdriver|__selenium|__driver|__nightmare)/.test(k)) return true; }
      return !!(window.document.$cdc_asdjflasutopfhvcZLmcfl_ || window.document.__webdriver_evaluate);
    }, false);
    t.headlessUA = safe(function () { return /HeadlessChrome|PhantomJS|Electron/i.test(navigator.userAgent); }, false);
    // A patched toString (stealth plugins rewrite native fns) loses "[native code]".
    t.toStringTampered = safe(function () {
      return Function.prototype.toString.toString().indexOf("[native code]") === -1 ||
             ("" + navigator.permissions.query).indexOf("[native code]") === -1;
    }, false);
    // Headless Chrome historically reports notification "denied" while permission "default".
    t.permissionsAnomaly = false; // filled async below if available
    t.noPlugins = safe(function () { return (navigator.plugins ? navigator.plugins.length : 0) === 0; }, false);
    t.noMimeTypes = safe(function () { return (navigator.mimeTypes ? navigator.mimeTypes.length : 0) === 0; }, false);
    t.languagesEmpty = safe(function () { return !navigator.languages || navigator.languages.length === 0; }, false);
    t.chromeMissing = safe(function () { return /Chrome\//.test(navigator.userAgent) && !window.chrome; }, false);
    // Software rasterizers used by headless / VM rendering.
    t.swRenderer = safe(function () {
      return /SwiftShader|llvmpipe|Software|Microsoft Basic Render|Mesa OffScreen/i.test(webglRenderer || "");
    }, false);
    t.zeroHardware = safe(function () {
      return navigator.hardwareConcurrency === 0 || navigator.deviceMemory === 0;
    }, false);
    return t;
  }

  function permissionAnomaly(tells, done) {
    // Once-only guard: this surface resolves from BOTH the permissions.query
    // promise AND the safety setTimeout, so without a settled flag it would call
    // `done` (buildStatic's shared counter step) ~twice — firing finalize() early,
    // before webgpu's 600ms requestAdapter resolves, silently dropping WebGPU.
    // The other three async surfaces (audio/webgpu/ua-CH) already guard this way.
    var settled = false;
    var finish = function () { if (!settled) { settled = true; done(); } };
    safe(function () {
      if (!navigator.permissions || !navigator.permissions.query) { finish(); return; }
      navigator.permissions.query({ name: "notifications" }).then(function (res) {
        tells.permissionsAnomaly = safe(function () {
          return Notification.permission === "denied" && res.state === "prompt";
        }, false);
        finish();
      }, function () { finish(); });
    }, finish);
    setTimeout(finish, 300);
  }

  function scoreAutomation(t) {
    var n = 0, keys = ["webdriver", "cdc", "headlessUA", "toStringTampered",
      "permissionsAnomaly", "noPlugins", "noMimeTypes", "languagesEmpty",
      "chromeMissing", "swRenderer", "zeroHardware"];
    for (var i = 0; i < keys.length; i++) { if (t[keys[i]]) n++; }
    return n;
  }

  // --- Behavioral biometrics ------------------------------------------------
  // Accumulate mouse/scroll/keystroke dynamics; summarized into the beacon.
  // We flag both non-human regularity AND signatures of synthetic humanization
  // (too-tidy distributions, perfectly smooth paths) per the reference doc.
  var behavior = {
    mouseEvents: 0, mouseDistance: 0, _lastX: null, _lastY: null,
    _angles: [], _intervals: [], _lastMoveT: null,
    clicks: 0, _clickT: [], scrollEvents: 0, maxScroll: 0,
    keyEvents: 0, _downAt: {}, _dwell: [], _flight: [], _lastUp: null
  };
  // Pauses longer than this aren't part of a motion stroke / typing burst — the
  // visitor stopped to read, or tabbed away and came back. Excluding them keeps
  // the inter-event regularity statistics (moveIntervalCv, meanFlight) describing
  // actual motor behavior; one multi-minute gap would otherwise swamp the
  // distributions the synthetic-humanization check reads.
  var IDLE_GAP_MS = 2000;
  function onMove(e) {
    behavior.mouseEvents++;
    var x = e.clientX, y = e.clientY, now = performance.now();
    if (behavior._lastX !== null) {
      var dx = x - behavior._lastX, dy = y - behavior._lastY;
      behavior.mouseDistance += Math.sqrt(dx * dx + dy * dy);
      if (dx || dy) behavior._angles.push(Math.atan2(dy, dx));
      if (behavior._lastMoveT !== null && (now - behavior._lastMoveT) < IDLE_GAP_MS) {
        behavior._intervals.push(now - behavior._lastMoveT);
      }
    }
    behavior._lastX = x; behavior._lastY = y; behavior._lastMoveT = now;
  }
  function onClick() { behavior.clicks++; behavior._clickT.push(performance.now()); }
  function onScroll() {
    behavior.scrollEvents++;
    behavior.maxScroll = Math.max(behavior.maxScroll, window.scrollY || 0);
  }
  function onKeyDown(e) { behavior._downAt[e.code || e.key] = performance.now(); }
  function onKeyUp(e) {
    behavior.keyEvents++;
    var k = e.code || e.key, now = performance.now();
    if (behavior._downAt[k] != null) { behavior._dwell.push(now - behavior._downAt[k]); delete behavior._downAt[k]; }
    if (behavior._lastUp != null && (now - behavior._lastUp) < IDLE_GAP_MS) {
      behavior._flight.push(now - behavior._lastUp);
    }
    behavior._lastUp = now;
  }
  function mean(a) { return a.length ? a.reduce(function (s, v) { return s + v; }, 0) / a.length : null; }
  function stdev(a) {
    if (a.length < 2) return null;
    var m = mean(a);
    return Math.sqrt(a.reduce(function (s, v) { return s + (v - m) * (v - m); }, 0) / a.length);
  }
  function entropy(a) {
    // Shannon entropy of binned turn-angles — humans are irregular, scripts tidy.
    if (!a.length) return null;
    var bins = {}, B = 16;
    for (var i = 0; i < a.length; i++) {
      var idx = Math.floor(((a[i] + Math.PI) / (2 * Math.PI)) * B) % B;
      bins[idx] = (bins[idx] || 0) + 1;
    }
    var h = 0;
    for (var k in bins) { var p = bins[k] / a.length; h -= p * Math.log2(p); }
    return Math.round(h * 1000) / 1000;
  }
  function behaviorSummary() {
    var meanTurn = mean(behavior._angles.map(function (a, i, arr) {
      return i ? Math.abs(arr[i] - arr[i - 1]) : 0;
    }).slice(1));
    var clickIvls = [];
    for (var i = 1; i < behavior._clickT.length; i++) clickIvls.push(behavior._clickT[i] - behavior._clickT[i - 1]);
    var moveStd = stdev(behavior._intervals);
    var moveMean = mean(behavior._intervals);
    var dwellStd = stdev(behavior._dwell), dwellMean = mean(behavior._dwell);
    // Synthetic-humanization heuristic: lots of motion that is *too* regular
    // (very low coefficient of variation in inter-event timing or keystroke
    // dwell) reads as injected/scripted rather than human.
    var synthetic = false;
    if (behavior.mouseEvents > 25 && moveMean && moveStd != null) {
      if ((moveStd / moveMean) < 0.05) synthetic = true;
    }
    if (behavior._dwell.length > 6 && dwellMean && dwellStd != null) {
      if ((dwellStd / dwellMean) < 0.04) synthetic = true;
    }
    return {
      mouseEvents: behavior.mouseEvents,
      mouseDistance: Math.round(behavior.mouseDistance),
      mousePathEntropy: entropy(behavior._angles),
      meanTurnAngle: meanTurn != null ? Math.round(meanTurn * 1000) / 1000 : null,
      moveIntervalCv: (moveMean && moveStd != null) ? Math.round((moveStd / moveMean) * 1000) / 1000 : null,
      clicks: behavior.clicks,
      meanClickInterval: clickIvls.length ? Math.round(mean(clickIvls)) : null,
      scrollEvents: behavior.scrollEvents,
      maxScroll: behavior.maxScroll,
      keyEvents: behavior.keyEvents,
      meanDwell: dwellMean != null ? Math.round(dwellMean * 100) / 100 : null,
      meanFlight: mean(behavior._flight) != null ? Math.round(mean(behavior._flight) * 100) / 100 : null,
      interacted: behavior.mouseEvents + behavior.clicks + behavior.scrollEvents + behavior.keyEvents > 0,
      synthetic: synthetic
    };
  }

  safe(function () {
    window.addEventListener("mousemove", onMove, { passive: true });
    window.addEventListener("click", onClick, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("keydown", onKeyDown, { passive: true });
    window.addEventListener("keyup", onKeyUp, { passive: true });
  });

  // --- Assemble + send ------------------------------------------------------
  var STATIC = null; // cached stable fingerprint (computed once)

  function buildStatic(done) {
    var canvas = canvasFingerprint();
    var webgl = webglFingerprint();
    var fonts = fontFingerprint();
    var screen = screenInfo();
    var nav = navigatorInfo();
    var tells = automationTells(webgl.renderer);
    // Resolve the three async surfaces (audio, webgpu, ua-CH, permissions) then assemble.
    var audio = null, webgpu = null, uaCH = null;
    var pending = 4;
    var step = function () { if (--pending === 0) finalize(); };
    audioFingerprint(function (a) { audio = a; step(); });
    webgpuFingerprint(null, function (g) { webgpu = g; step(); });
    uaClientHints(function (h) { uaCH = h; step(); });
    permissionAnomaly(tells, function () { step(); });

    function finalize() {
      tells.score = scoreAutomation(tells);
      nav.uaCH = uaCH;
      var fpId = cyrb53([
        canvas.hash, webgl.hash, audio && audio.hash, fonts.hash,
        nav.platform, nav.hardwareConcurrency, nav.deviceMemory, nav.timezone,
        screen.w, screen.h, screen.dpr, (nav.languages || []).join(",")
      ].join("|"));
      // Persist the device id in a cookie so the honeypot server can serve the
      // SAME canary tokens to this device even when it later rotates its exit IP
      // (VPN) or User-Agent: a returning browser carries this cookie and
      // server.py keys the canary row on it (falling back to (UA, ASN) when it's
      // absent). A non-JS scraper never runs this, so it keeps the old keying and
      // its very absence stays a signal. Best-effort; a storage failure is ignored.
      safe(function () {
        document.cookie = "__abd_fp=" + fpId + ";path=/;max-age=31536000;SameSite=Lax";
      });
      STATIC = {
        v: 1,
        fp_id: fpId,
        canvas_hash: canvas.hash, canvas_winding: canvas.winding,
        webgl_hash: webgl.hash, webgl_vendor: webgl.vendor, webgl_renderer: webgl.renderer,
        webgl_params: webgl.params, webgl_extensions: webgl.extensions, webgl_shader_ms: webgl.shaderMs,
        webgpu: webgpu,
        audio_hash: audio && audio.hash, audio_sample: audio && audio.sample,
        fonts: fonts.fonts, font_hash: fonts.hash,
        screen: screen, navigator: nav, automation: tells
      };
      done(STATIC);
    }
  }

  // Random id shared by every beacon THIS page load emits (the load beacon plus
  // each re-armed unload beacon). Beacons of one pageview all carry the same
  // pv_id, so the request log can attach the LATEST cumulative beacon of the
  // right pageview — instead of just the nearest in time, which could be the
  // *previous* page's unload beacon (it fires the instant this page was
  // navigated to) or a stale early snapshot of this one.
  var PV_ID = safe(function () {
    var a = new Uint32Array(2);
    crypto.getRandomValues(a);
    return a[0].toString(16) + a[1].toString(16);
  }, null) || (Date.now().toString(16) + Math.floor(Math.random() * 0xffffffff).toString(16));

  function payload(phase) {
    var p = {};
    for (var k in STATIC) { p[k] = STATIC[k]; }
    p.phase = phase;
    p.pv_id = PV_ID;
    p.ts_client = Date.now();
    p.url = location.pathname;
    p.referrer = document.referrer || null;
    p.behavior = behaviorSummary();
    return p;
  }

  function sendBeacon(phase, useNavBeacon) {
    var body = safe(function () { return JSON.stringify(payload(phase)); }, null);
    if (!body) return;
    if (useNavBeacon && navigator.sendBeacon) {
      safe(function () { navigator.sendBeacon(BEACON_PATH, new Blob([body], { type: "application/json" })); });
      return;
    }
    safe(function () {
      fetch(BEACON_PATH, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: body, keepalive: true, credentials: "omit", cache: "no-store"
      }).catch(function () {});
    });
  }

  function start() {
    buildStatic(function () {
      setTimeout(function () { sendBeacon("load", false); }, SETTLE_MS);
    });
    // Interaction total at the moment of the last unload beacon. Deliberately NOT
    // a one-shot boolean: the old `flushed` flag meant the FIRST tab-away sent the
    // biometrics and every later one sent nothing — so a visitor who tabbed away,
    // came back, and kept interacting had all of that later behavior silently
    // lost. Now each hide/pagehide flushes an updated *cumulative* beacon, but
    // only when new interaction accumulated since the last one (a hide with
    // nothing new is suppressed, so tabbing in/out doesn't emit duplicates).
    var flushedAt = -1;
    var flush = function () {
      if (!STATIC) return;
      var total = behavior.mouseEvents + behavior.clicks + behavior.scrollEvents + behavior.keyEvents;
      if (total === flushedAt) return;
      flushedAt = total;
      sendBeacon("unload", true);
    };
    window.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden") flush();
    });
    window.addEventListener("pagehide", flush);
  }

  if (document.body) { start(); }
  else { window.addEventListener("DOMContentLoaded", start); }
})();
