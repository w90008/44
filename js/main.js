// main.js — driver halaman browser PS4 13.00 (port dari loader.ts versi lite).
// Dimuat PALING AKHIR: saat file ini jalan, userland.js sudah mencapai ARW
// (make_uaf -> master/slave -> leak jsc/libc/libkernel), dan semua fungsi
// exploit (checkJailbroken, get_fwversion, netctrl_exploit, binloader_init)
// sudah terdefinisi sebagai global.

// ---- penanda sukses: netctrl memanggil binloader_init() sendiri setelah jailbreak ----
var _binloaderInitOrig = binloader_init
binloader_init = function () {
  log('ALL DONE')
  _binloaderInitOrig.apply(null, arguments)
}

// ---- ambil goldhen.bin dari server HTTP (dilakukan SEKARANG, sebelum exploit,
//      saat proses masih sandbox dan halaman masih bisa fetch same-origin) ----
var goldhenBuf = null
try {
  var xhr = new XMLHttpRequest()
  xhr.open('GET', 'goldhen.bin', false) // sinkron — paling andal di WebKit tua
  xhr.responseType = 'arraybuffer'
  xhr.send()
  if (xhr.status === 200 && xhr.response && xhr.response.byteLength > 0) {
    goldhenBuf = xhr.response
    log('goldhen.bin terunduh: ' + goldhenBuf.byteLength + ' bytes')
  } else {
    log('GAGAL unduh goldhen.bin (status ' + xhr.status + ')')
  }
} catch (e) {
  log('GAGAL unduh goldhen.bin: ' + e)
}

// ---- mulai rantai ----
// FW_VERSION = global yang dipakai netctrl_exploit() (di Vue didefinisikan loader.ts;
// di sini loader.ts tidak dimuat, jadi kita definisikan sendiri).
var FW_VERSION = null
try { FW_VERSION = get_fwversion() } catch (e) {}
log('Firmware: ' + FW_VERSION)

var is_jailbroken = checkJailbroken()
if (is_jailbroken) {
  log('Sudah jailbreak — muat payload langsung')
  binloader_init()
} else {

  log('running the primitive...')
  // (userland sudah selesai dieksekusi saat userland.js dimuat)

  log('make_karw...')
  // netctrl_exploit(): kernel stage lengkap (triple-free ucred -> kqueue ->
  // pipebuf R/W -> patch ucred -> sandbox escape), lalu memanggil
  // binloader_init() sendiri di akhir -> muat goldhen.bin dari HTTP.
  netctrl_exploit()
}
