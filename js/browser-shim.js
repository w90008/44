// browser-shim.js — shim pengganti environment Vue (jsmaf) untuk browser WebKit PS4.
// WAJIB dimuat PALING AWAL, sebelum semua script exploit (types/defs/userland/...).
//
// Basis port: github.com/owendswang/vue-after-free-lite (2026-04-17)
// API Vue yang dipakai script exploit dan digantikan di sini:
//   include(), log(), debug(), error(), jsmaf.setTimeout/clearTimeout, ws.broadcast.
// Catatan: netctrl versi lite sudah TIDAK memakai jsmaf.root/Text/Image/Style (UI dibuang),
// sehingga shim ini kecil.

// ---- log ke area <pre id="log"> ----
var _logBuf = []
function _logFlush () {
  var el = document.getElementById('log')
  if (el) el.textContent = _logBuf.join('\n')
}
function log (msg) {
  _logBuf.push(String(msg))
  _logFlush()
  try { console.log(msg) } catch (e) {}
}
function debug (msg) {
  _logBuf.push('[dbg] ' + String(msg))
  _logFlush()
}
function error (msg) {
  _logBuf.push('[ERROR] ' + String(msg))
  _logFlush()
  try { console.error(msg) } catch (e) {}
}

// include() di Vue memuat script lain ke scope global. Di browser semua script
// sudah dimuat berurutan lewat <script>, jadi no-op.
function include () {}

// ---- jsmaf shim ----
// Dipakai: netctrl (yield_to_render), binloader (penundaan autoclose).
var jsmaf = {
  setTimeout: function (cb, ms) { return window.setTimeout(cb, ms) },
  clearTimeout: function (id) { window.clearTimeout(id) },
  setInterval: function (cb, ms) { return window.setInterval(cb, ms) },
  clearInterval: function (id) { window.clearInterval(id) }
}

// ---- ws shim ----
// Cadangan kalau ada sisa referensi log jarak jauh (WebUI Vue). Lite sudah
// tidak memakainya, tapi definisi ini menjaga kalau versi netctrl berganti.
var ws = {
  broadcast: function (msg) {
    try { console.log('[ws] ' + msg) } catch (e) {}
  }
}
