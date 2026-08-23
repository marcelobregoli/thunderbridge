// ==UserScript==
// @name         thunderbridge HV token capture
// @namespace    thunderbridge
// @match        https://verify.proton.me/*
// @run-at       document-start
// @grant        GM_xmlhttpRequest
// @connect      127.0.0.1
// @connect      localhost
// ==/UserScript==
//
// Runs on verify.proton.me. The user solves the CAPTCHA MANUALLY; the page sends the
// solved token to window.parent via postMessage. This script hooks that postMessage
// (in page context via unsafeWindow) and automatically POSTs the token to
// thunderbridge's local listener (127.0.0.1:8722). No automated solving — only the
// delivery is automated.

(function () {
  'use strict';

  const PORT = 8722;
  const seen = new Set();

  function deliver(token) {
    if (!token || seen.has(token)) return;
    seen.add(token);
    console.log('%c[thunderbridge] token captured -> sending to thunderbridge', 'color:#0f0');
    try {
      GM_xmlhttpRequest({
        method: 'POST',
        url: 'http://127.0.0.1:' + PORT + '/token',
        data: token,
        headers: { 'Content-Type': 'text/plain' },
        onload: function () {
          banner('Sent to thunderbridge — you can return to the terminal.', '#0b3d0b');
        },
        onerror: function () {
          banner('Could not reach thunderbridge (is `auth` running?). Token:\n' + token, '#5a1a1a');
        },
      });
    } catch (e) {
      banner('GM_xmlhttpRequest unavailable. Token (paste it manually):\n' + token, '#5a1a1a');
    }
  }

  function banner(msg, bg) {
    let box = document.getElementById('tb-token-box');
    if (!box) {
      box = document.createElement('div');
      box.id = 'tb-token-box';
      box.style.cssText =
        'position:fixed;top:0;left:0;right:0;z-index:2147483647;color:#e6ffe6;' +
        'font:14px/1.4 monospace;padding:12px;word-break:break-all;white-space:pre-wrap';
      (document.body || document.documentElement).appendChild(box);
    }
    box.style.background = bg;
    box.textContent = 'thunderbridge: ' + msg;
  }

  function fromMessage(m) {
    if (!m) return null;
    if (typeof m === 'string') {
      try { m = JSON.parse(m); } catch (_) { return null; }
    }
    if (typeof m !== 'object') return null;
    const token = m.token || (m.payload && m.payload.token) || (m.data && m.data.token);
    if (!token) return null;
    // Proton delivers the solved token as {type:'pm_captcha', token} and
    // {type:'HUMAN_VERIFICATION_SUCCESS', payload:{token,...}}. Accept either by the
    // message kind, and fall back to a substring check for other/newer shapes.
    const kind = String(m.type || (m.payload && m.payload.type) || '');
    if (/captcha|human[_-]?verification/i.test(kind)) return token;
    if (/captcha|human[_-]?verification/i.test(JSON.stringify(m))) return token;
    return null;
  }

  const w = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;

  // Hook the postMessage SEND path (the page uses window.parent.postMessage; in
  // standalone mode parent === self, targetOrigin '*').
  function hook(target) {
    try {
      const orig = target.postMessage;
      if (!orig || orig.__tb) return;
      const hooked = function (m) {
        const t = fromMessage(m);
        if (t) deliver(t);
        return orig.apply(this, arguments);
      };
      hooked.__tb = true;
      target.postMessage = hooked;
    } catch (_) {}
  }
  hook(w);
  try { hook(w.parent); } catch (_) {}
  try { hook(w.top); } catch (_) {}

  // Classic listener (for cases posted to the same origin).
  w.addEventListener('message', function (e) {
    const t = fromMessage(e.data);
    if (t) { deliver(t); return; }
    // Surface unrecognized messages so a future format change is easy to diagnose.
    try {
      const d = e.data;
      const kind = d && (d.type || (d.payload && d.payload.type));
      if (kind) console.debug('[thunderbridge] ignored message:', kind);
    } catch (_) {}
  }, true);

  console.log('%c[thunderbridge] HV capture active — solve the CAPTCHA, the rest is automatic.', 'color:#0f0');
})();
