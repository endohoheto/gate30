// The password form of the protected build (tools/build-locked.py).
//
// On the server everything inside the book is AES-256-GCM encrypted under a key derived
// from the password, and only the cover and the share card can be read. This derives the
// key, decrypts the scripts, and hands book.js a way to get any other file as a blob: URL
// (window.GATE30_ASSET). A key that worked is kept on the device, so the book opens
// without asking again; a new password (a rebuild with a new salt) asks again.
(() => {
  'use strict';
  const L = window.GATE30_LOCK;          // { salt, iter, manifest } written by the build
  const $ = (id) => document.getElementById(id);
  const form = $('lock');
  const input = $('lock-pw');
  const msg = $('lock-msg');
  const SAVED = 'gate30.key.' + L.salt;
  const saved = {
    get() { try { return localStorage.getItem(SAVED); } catch { return null; } },
    set(v) { try { localStorage.setItem(SAVED, v); } catch { /* private mode: ask each time */ } },
    drop() { try { localStorage.removeItem(SAVED); } catch { /* nothing kept */ } },
  };
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const TYPES = { webp: 'image/webp', mp4: 'video/mp4', js: 'text/javascript' };

  function say(text, wait) {
    msg.textContent = text;
    msg.classList.toggle('wait', !!wait);
  }

  async function derive(pw) {
    // trimmed and NFC, as the build does: a password pasted from a message often
    // carries a stray space or newline
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw.trim().normalize('NFC')),
      'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(L.salt), iterations: L.iter },
      base, 256);
  }

  const get = (name) => fetch('enc/' + name).then((r) => {
    if (!r.ok) throw new Error(`enc/${name}: ${r.status}`);
    return r.arrayBuffer();
  });
  // a file is the 12-byte IV followed by the ciphertext and tag
  const opener = (key) => (buf) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(buf, 0, 12) },
    key, new Uint8Array(buf, 12));

  async function unlock(raw) {
    const open = opener(await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']));
    // a wrong key fails here, with an OperationError from the tag check
    const files = JSON.parse(new TextDecoder().decode(await open(await get(L.manifest))));
    const urls = new Map();
    window.GATE30_ASSET = (path) => {
      if (!urls.has(path)) {
        const name = files[path];
        // not in the manifest: one of the few files left readable (the cover), served as is
        urls.set(path, name
          ? get(name).then(open).then((d) => URL.createObjectURL(new Blob([d], { type: TYPES[path.split('.').pop()] || '' })))
          : Promise.resolve(path));
      }
      return urls.get(path);
    };
    const code = await Promise.all(['book-data.js', 'content.js', 'img/sizes.js', 'book.js']
      .map((p) => get(files[p]).then(open).then((d) => new TextDecoder().decode(d))));
    return () => code.forEach((c) => {
      const s = document.createElement('script');
      s.textContent = c;
      document.body.append(s);
    });
  }

  function opened(run) {
    form.hidden = true;
    document.querySelectorAll('[data-locked]').forEach((e) => { e.hidden = false; });
    run();                                // book.js wires up OPEN, or opens a #link itself
  }

  async function tryKey(raw, typed) {
    let run;
    try {
      run = await unlock(raw);
    } catch (e) {
      if (e && e.name === 'OperationError') {
        saved.drop();
        if (typed) say('パスワードが違います');
        else say('');
      } else {
        say('読み込めませんでした。通信を確かめて、もう一度どうぞ');
      }
      return false;
    }
    saved.set(toB64(raw));
    opened(run);
    return true;
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!input.value.trim()) { input.focus(); return; }
    const btn = form.querySelector('button');
    btn.disabled = true;
    say('確かめています…', true);
    try {
      const ok = await tryKey(await derive(input.value), true);
      if (!ok) { input.select(); }
    } finally {
      btn.disabled = false;
    }
  });

  if (!window.crypto || !crypto.subtle) {
    // only over https (or localhost); a copy opened from disk cannot decrypt
    say('このページは https で開いてください');
    form.querySelector('button').disabled = true;
    return;
  }
  const kept = saved.get();
  if (kept) {
    form.hidden = true;
    tryKey(fromB64(kept), false).then((ok) => { if (!ok) { form.hidden = false; } });
  }
})();
