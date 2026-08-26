// bin_loader.js - ELF/binary loader for PS4 after vue-after-free jailbreak
// Ported from netflix N Hack for ps4
//
// Usage: include('binloader.js') before userland/lapse
//        After lapse completes, call: binloader_init()

// Define binloader_init function
function binloader_init(payloadSelect) {
  debug('binloader_init(): Initializing binloader...');

  // Check dependencies
  if (typeof fn === 'undefined') {
    error('ERROR: fn object is undefined! userland.js not loaded?');
    throw new Error('fn object not available - cannot initialize binloader');
  }
  debug('binloader_init(): Dependencies OK, initializing...');
  var thrd_create = fn.thrd_create;
  var thrd_join = fn.thrd_join;
  var stat_sys = fn.stat_sys;
  var open_sys = fn.open_sys;
  var read_sys = fn.read_sys;
  var write_sys = fn.write_sys;
  var close_sys = fn.close_sys;
  var mmap_sys = fn.mmap_sys;
  var bind_sys = fn.bind_sys;
  var listen_sys = fn.listen_sys;
  var accept_sys = fn.accept_sys;
  var connect_sys = fn.connect_sys;
  var socket = fn.socket;
  var setsockopt = fn.setsockopt;
  // const exit_sys = fn.exit_sys
  var nanosleep_sys = fn.nanosleep_sys;
  // const thr_exit_sys = fn.thr_exit_sys

  // Constants
  var BIN_LOADER_PORT = 9020;
  var MAX_PAYLOAD_SIZE = 4 * 1024 * 1024; // 4MB max
  var READ_CHUNK = 32768; // 32KB chunks for faster transfer
  var PAGE_SIZE = 16384; // PS4 page size

  // ELF magic bytes
  var ELF_MAGIC = 0x464C457F; // "\x7fELF" as little-endian uint32

  // mmap constants
  var BL_MAP_PRIVATE = 0x2;
  var BL_MAP_ANONYMOUS = 0x1000;
  var BL_PROT_READ = 0x1;
  var BL_PROT_WRITE = 0x2;
  var BL_PROT_EXEC = 0x4;

  // Socket constants
  var BL_AF_INET = 2;
  var BL_SOCK_STREAM = 1;
  var BL_SOL_SOCKET = 0xffff;
  var BL_SO_REUSEADDR = 4;

  // File open flags
  var BL_O_RDONLY = 0;
  var BL_O_WRONLY = 1;
  var BL_O_RDWR = 2;
  var BL_O_CREAT = 0x200;
  var BL_O_TRUNC = 0x400;

  // USB and data paths (check usb0-usb4 like BD-JB does)
  var USB_PAYLOAD_PATHS = ['/mnt/usb0/payload.bin', '/mnt/usb1/payload.bin', '/mnt/usb2/payload.bin', '/mnt/usb3/payload.bin', '/mnt/usb4/payload.bin', '/mnt/usb0/payload.bin.bin', '/mnt/usb1/payload.bin.bin', '/mnt/usb2/payload.bin.bin',
  // yes we have to do this 😅
  '/mnt/usb3/payload.bin.bin', '/mnt/usb4/payload.bin.bin'];
  var DATA_PAYLOAD_PATH = '/data/payload.bin';
  var SANDBOX_PAYLOAD_PATH = '/mnt/sandbox/download/CUSA00960/payload.bin';

  // S_ISREG macro check - file type is regular file
  var S_IFREG = 0x8000;

  // ELF header structure offsets
  var ELF_HEADER = {
    E_ENTRY: 0x18,
    E_PHOFF: 0x20,
    E_SHOFF: 0x28,
    E_PHENTSIZE: 0x36,
    E_PHNUM: 0x38,
    E_SHENTSIZE: 0x3A,
    E_SHNUM: 0x3C
  };

  // Program header structure offsets
  var PROGRAM_HEADER = {
    P_TYPE: 0x00,
    P_FLAGS: 0x04,
    P_OFFSET: 0x08,
    P_VADDR: 0x10,
    P_FILESZ: 0x20,
    P_MEMSZ: 0x28
  };

  // Section header structure offsets
  var SECTION_HEADER = {
    SH_TYPE: 0x04,
    SH_OFFSET: 0x18,
    SH_SIZE: 0x20,
    SH_ENTSIZE: 0x38
  };

  // Relocation entry structure offsets
  var RELA_ENTRY = {
    R_OFFSET: 0x00,
    R_INFO: 0x08,
    R_ADDEND: 0x10
  };
  var PT_LOAD = 1;
  var SHT_RELA = 4;
  var R_X86_64_RELATIVE = 8;

  // Helper: Round up to page boundary
  function bl_round_up(x, base) {
    return Math.floor((x + base - 1) / base) * base;
  }

  // Helper: Check for syscall error
  function bl_is_error(val) {
    if (val instanceof BigInt) {
      return val.hi === 0xffffffff;
    }
    return val === -1 || val === 0xffffffff;
  }

  // Helper: Allocate string in memory and return address
  function bl_alloc_string(str) {
    var addr = mem.malloc(str.length + 1);
    for (var i = 0; i < str.length; i++) {
      mem.view(addr).setUint8(i, str.charCodeAt(i));
    }
    mem.view(addr).setUint8(str.length, 0); // null terminator
    return addr;
  }

  // Helper: Check if file exists using stat() and return size, or -1 if not found
  function bl_file_exists(path) {
    debug('Checking: ' + path);
    var path_addr = bl_alloc_string(path);
    var stat_buf = mem.malloc(0x78);

    // Call stat(path, &stat_buf) - catch errors (file not found)
    try {
      var ret = stat_sys(path_addr, stat_buf);
      if (bl_is_error(ret)) {
        debug('  stat() failed - file not found');
        return -1;
      }

      // Check st_mode at offset 0x08 to see if it's a regular file
      var st_mode = mem.view(stat_buf).getUint16(0x08, true);

      // Check S_ISREG (mode & 0xF000) == S_IFREG (0x8000)
      if ((st_mode & 0xF000) !== S_IFREG) {
        debug('  Not a regular file (st_mode=0x' + st_mode.toString(16) + ')');
        return -1;
      }

      // st_size is at offset 0x48 in struct stat (int64_t)
      var size = mem.view(stat_buf).getBigInt(0x48, true);
      var size_num = size.lo + size.hi * 0x100000000;
      debug('  Found: ' + size_num + ' bytes');
      return size_num;
    } catch (e) {
      error('  ' + e.message);
      return -1;
    }
  }

  // Get file size using stat()
  function bl_get_file_size_stat(path) {
    var path_addr = bl_alloc_string(path);
    var stat_buf = mem.malloc(0x78);
    try {
      var ret = stat_sys(path_addr, stat_buf);
      if (bl_is_error(ret)) {
        return -1;
      }

      // st_size is at offset 0x48
      var size = mem.view(stat_buf).getBigInt(0x48, true);
      return size.lo + size.hi * 0x100000000;
    } catch (e) {
      return -1;
    }
  }

  // Read entire file into memory buffer
  function bl_read_file(path) {
    // Use stat() to get file size
    var size = bl_get_file_size_stat(path);
    if (size <= 0) {
      error('  stat failed or size=0');
      return null;
    }
    var path_addr = bl_alloc_string(path);
    var fd = open_sys(path_addr, new BigInt(0, BL_O_RDONLY), new BigInt(0, 0));
    if (bl_is_error(fd)) {
      error('  open failed');
      return null;
    }
    var fd_num = fd instanceof BigInt ? fd.lo : fd;
    var buf = mem.malloc(size);
    var total_read = 0;
    while (total_read < size) {
      var chunk = size - total_read > READ_CHUNK ? READ_CHUNK : size - total_read;
      var bytes_read = read_sys(new BigInt(0, fd_num), buf.add(new BigInt(0, total_read)), new BigInt(0, chunk));
      if (bl_is_error(bytes_read) || bytes_read.eq(0)) {
        break;
      }
      total_read += bytes_read.lo;
    }
    close_sys(fd_num);
    if (total_read !== size) {
      error('  read incomplete: ' + total_read + '/' + size);
      return null;
    }
    return {
      buf,
      size
    };
  }

  // Write buffer to file
  function bl_write_file(path, buf, size) {
    var path_addr = bl_alloc_string(path);
    var flags = BL_O_WRONLY | BL_O_CREAT | BL_O_TRUNC;
    debug('  write_file: open(' + path + ', flags=0x' + flags.toString(16) + ')');
    var fd = open_sys(path_addr, new BigInt(0, flags), new BigInt(0, 0o755));
    var fd_num = fd instanceof BigInt ? fd.lo : fd;
    debug('  write_file: fd=' + fd_num);
    if (bl_is_error(fd)) {
      error('  write_file: open failed');
      return false;
    }
    var total_written = 0;
    while (total_written < size) {
      var chunk = size - total_written > READ_CHUNK ? READ_CHUNK : size - total_written;
      var bytes_written = write_sys(new BigInt(0, fd_num), buf.add(new BigInt(0, total_written)), new BigInt(0, chunk));
      if (bl_is_error(bytes_written) || bytes_written.eq(0)) {
        error('  write_file: write failed at ' + total_written + '/' + size);
        close_sys(fd_num);
        return false;
      }
      total_written += bytes_written.lo;
    }
    close_sys(fd_num);
    debug('  write_file: wrote ' + total_written + ' bytes');
    return true;
  }

  // Copy file from src to dst
  function bl_copy_file(src_path, dst_path) {
    log('Copying ' + src_path + ' -> ' + dst_path);
    var data = bl_read_file(src_path);
    if (data === null) {
      error('Failed to read source file');
      return false;
    }
    log('Read ' + data.size + ' bytes');
    if (!bl_write_file(dst_path, data.buf, data.size)) {
      error('Failed to write destination file');
      return false;
    }
    log('Copy complete');
    return true;
  }

  // Read ELF header from buffer
  function bl_read_elf_header(buf_addr) {
    return {
      magic: mem.view(buf_addr).getUint32(0, true),
      e_entry: mem.view(buf_addr).getBigInt(ELF_HEADER.E_ENTRY, true),
      e_phoff: mem.view(buf_addr).getBigInt(ELF_HEADER.E_PHOFF, true),
      e_shoff: mem.view(buf_addr).getBigInt(ELF_HEADER.E_SHOFF, true),
      e_phentsize: mem.view(buf_addr).getUint16(ELF_HEADER.E_PHENTSIZE, true),
      e_phnum: mem.view(buf_addr).getUint16(ELF_HEADER.E_PHNUM, true),
      e_shentsize: mem.view(buf_addr).getUint16(ELF_HEADER.E_SHENTSIZE, true),
      e_shnum: mem.view(buf_addr).getUint16(ELF_HEADER.E_SHNUM, true)
    };
  }

  // Read program header from buffer
  function bl_read_program_header(buf_addr, offset) {
    var base = buf_addr.add(new BigInt(0, offset));
    return {
      p_type: mem.view(base).getUint32(PROGRAM_HEADER.P_TYPE, true),
      p_flags: mem.view(base).getUint32(PROGRAM_HEADER.P_FLAGS, true),
      p_offset: mem.view(base).getBigInt(PROGRAM_HEADER.P_OFFSET, true),
      p_vaddr: mem.view(base).getBigInt(PROGRAM_HEADER.P_VADDR, true),
      p_filesz: mem.view(base).getBigInt(PROGRAM_HEADER.P_FILESZ, true),
      p_memsz: mem.view(base).getBigInt(PROGRAM_HEADER.P_MEMSZ, true)
    };
  }

  // Read section header from buffer
  function bl_read_section_header(buf_addr, offset) {
    var base = buf_addr.add(new BigInt(0, offset));
    var view = mem.view(base);
    return {
      sh_type: view.getUint32(SECTION_HEADER.SH_TYPE, true),
      sh_offset: view.getBigInt(SECTION_HEADER.SH_OFFSET, true),
      sh_size: view.getBigInt(SECTION_HEADER.SH_SIZE, true),
      sh_entsize: view.getBigInt(SECTION_HEADER.SH_ENTSIZE, true)
    };
  }

  // Read relocation entry from buffer
  function bl_read_relocation_entry(buf_addr, offset) {
    var base = buf_addr.add(new BigInt(0, offset));
    return {
      r_offset: mem.view(base).getBigInt(RELA_ENTRY.R_OFFSET, true),
      r_info: mem.view(base).getBigInt(RELA_ENTRY.R_INFO, true),
      r_addend: mem.view(base).getBigInt(RELA_ENTRY.R_ADDEND, true)
    };
  }

  // Load ELF segments into mmap'd memory
  function bl_load_elf_segments(buf_addr, base_addr) {
    var elf = bl_read_elf_header(buf_addr);
    debug('ELF: ' + elf.e_phnum + ' segments, entry @ ' + elf.e_entry.toString());
    for (var i = 0; i < elf.e_phnum; i++) {
      var phdr_offset = elf.e_phoff.lo + elf.e_phoff.hi * 0x100000000 + i * elf.e_phentsize;
      var segment = bl_read_program_header(buf_addr, phdr_offset);
      if (segment.p_type === PT_LOAD && !segment.p_memsz.eq(0)) {
        // Use lower 24 bits of vaddr to get offset within region
        var seg_offset_num = segment.p_vaddr.lo & 0xffffff;
        var seg_addr = base_addr.add(new BigInt(0, seg_offset_num));

        // Copy segment data
        var filesz = segment.p_filesz.lo + segment.p_filesz.hi * 0x100000000;
        var src_addr = buf_addr.add(segment.p_offset);

        // Copy using mem API
        for (var j = 0; j < filesz; j++) {
          var byte = mem.view(src_addr).getUint8(j);
          mem.view(seg_addr).setUint8(j, byte);
        }

        // Zero remaining memory (memsz - filesz)
        var memsz = segment.p_memsz.lo + segment.p_memsz.hi * 0x100000000;
        if (memsz > filesz) {
          for (var _j = filesz; _j < memsz; _j++) {
            mem.view(seg_addr).setUint8(_j, 0);
          }
        }
      }
    }

    // Apply relocations
    for (var _i = 0; _i < elf.e_shnum; _i++) {
      var shdr_offset = elf.e_shoff.lo + elf.e_shoff.hi * 0x100000000 + _i * elf.e_shentsize;
      var shdr = bl_read_section_header(buf_addr, shdr_offset);
      if (shdr.sh_type !== SHT_RELA) {
        continue;
      }
      for (var off = 0; off < shdr.sh_size.lo + shdr.sh_size.hi * 0x100000000; off += shdr.sh_entsize) {
        var rela_offset = off + shdr.sh_offset.lo + shdr.sh_offset.hi * 0x100000000;
        var rela = bl_read_relocation_entry(buf_addr, rela_offset);
        if (rela.r_info.lo === R_X86_64_RELATIVE) {
          var loc = base_addr.add(rela.r_offset);
          var val = base_addr.add(rela.r_addend);
          mem.view(loc).setBigInt(0, val, true);
        }
      }
    }

    // Return entry point address
    var entry_offset = elf.e_entry.lo & 0xffffff;
    return base_addr.add(new BigInt(0, entry_offset));
  }
  function bl_sleep_ms(ms) {
    var ts = mem.malloc(16);
    mem.view(ts).setBigInt(0, new BigInt(0, Math.floor(ms / 1000)), true);
    mem.view(ts).setBigInt(8, new BigInt(0, ms % 1000 * 1000000), true);
    nanosleep_sys(ts, new BigInt(0, 0));
  }
  function bl_autoclose(delayMs) {
    log('Auto closing - terminating current process');
    bl_sleep_ms(delayMs);
    var pid = fn.getpid();
    var pid_num = pid.lo;
    var kr = fn.kill(pid_num, 9);
    log('kill ret=' + kr.toString());
    // exit_sys(0)
  }

  // BinLoader object
  var BinLoader = {
    data: null,
    data_size: 0,
    mmap_base: null,
    mmap_size: 0,
    entry_point: null,
    skip_autoclose: false,
    init: function (bin_data_addr, bin_size) {
      this.data = bin_data_addr;
      this.data_size = bin_size;

      // Calculate mmap size (round up to page boundary)
      this.mmap_size = bl_round_up(bin_size, PAGE_SIZE);

      // Allocate RWX memory using mmap
      var prot = new BigInt(0, BL_PROT_READ | BL_PROT_WRITE | BL_PROT_EXEC);
      var flags = new BigInt(0, BL_MAP_PRIVATE | BL_MAP_ANONYMOUS);
      var ret = mmap_sys(new BigInt(0, 0), new BigInt(0, this.mmap_size), prot, flags, new BigInt(0xffffffff, 0xffffffff),
      // fd = -1
      new BigInt(0, 0));
      if (bl_is_error(ret)) {
        throw new Error('mmap failed: ' + ret.toString());
      }
      this.mmap_base = ret;
      debug('mmap() allocated at: ' + this.mmap_base.toString());

      // Check for ELF magic
      var magic = mem.view(bin_data_addr).getUint32(0, true);
      if (magic === ELF_MAGIC) {
        debug('Detected ELF binary, parsing headers...');
        this.entry_point = bl_load_elf_segments(bin_data_addr, this.mmap_base);
      } else {
        debug('Non-ELF binary, treating as raw shellcode (' + bin_size + ' bytes)');
        // Copy raw binary
        for (var i = 0; i < bin_size; i++) {
          var byte = mem.view(bin_data_addr).getUint8(i);
          mem.view(this.mmap_base).setUint8(i, byte);
        }
        this.entry_point = this.mmap_base;
      }
      debug('Entry point: ' + this.entry_point.toString());
    },
    run: function () {
      if (this.entry_point === null) {
        throw new Error('BinLoader not initialized properly - no entry point');
      }
      debug('Spawning payload thread using thrd_create...');

      // Allocate thread handle and result storage
      var thread_handle = mem.malloc(8); // thrd_t handle
      var thread_result = mem.malloc(4); // int result

      // Initialize to 0
      mem.view(thread_handle).setBigInt(0, new BigInt(0, 0), true);
      mem.view(thread_result).setUint32(0, 0, true);
      debug('Entry point @ ' + this.entry_point.toString());

      // Call thrd_create(thread_handle, entry_point, NULL)
      // int thrd_create(thrd_t *thr, thrd_start_t func, void *arg);
      debug('Calling thrd_create...');
      var ret = thrd_create(thread_handle,
      // thrd_t *thr
      this.entry_point,
      // thrd_start_t func
      new BigInt(0, 0) // void *arg (NULL)
      );

      // thrd_success = 0
      if (ret.eq(0)) {
        log('SUCCESS: Payload thread created!');
        var thr_id = mem.view(thread_handle).getBigInt(0, true);
        debug('Thread handle: ' + thr_id.toString());
        // utils.notify("Payload loaded!\nThread spawned successfully");

        // Call thrd_join to wait for thread completion
        // int thrd_join(thrd_t thr, int *res);
        debug('Waiting for thread to complete (thrd_join)...');
        var join_ret = thrd_join(thr_id,
        // thrd_t thr
        thread_result // int *res
        );
        if (join_ret.eq(0)) {
          var result_val = mem.view(thread_result).getUint32(0, true);
          debug('Thread completed successfully with result: ' + result_val);
        } else {
          log('WARNING: thrd_join returned: ' + join_ret.toString());
        }
        log('Binloader complete - thread has finished');

        // Check if autoclose is enabled
        if (!BinLoader.skip_autoclose) {
          bl_autoclose(3000);
        }
      } else {
        error('ERROR: thrd_create failed with return value: ' + ret.toString());
        throw new Error('Failed to spawn payload thread');
      }
    }
  };

  // Create listening socket
  function bl_create_listen_socket(port) {
    var sd = socket(BL_AF_INET, BL_SOCK_STREAM, 0);
    var sd_num = sd instanceof BigInt ? sd.lo : sd;
    if (bl_is_error(sd)) {
      throw new Error('socket() failed');
    }

    // Set SO_REUSEADDR
    var enable = mem.malloc(4);
    mem.view(enable).setUint32(0, 1, true);
    setsockopt(sd_num, BL_SOL_SOCKET, BL_SO_REUSEADDR, enable, 4);

    // Build sockaddr_in
    var sockaddr = mem.malloc(16);
    for (var j = 0; j < 16; j++) {
      mem.view(sockaddr).setUint8(j, 0);
    }
    mem.view(sockaddr).setUint8(1, 2); // AF_INET
    mem.view(sockaddr).setUint8(2, port >> 8 & 0xff); // port high byte
    mem.view(sockaddr).setUint8(3, port & 0xff); // port low byte
    mem.view(sockaddr).setUint32(4, 0, true); // INADDR_ANY

    var ret = bind_sys(new BigInt(0, sd_num), sockaddr, new BigInt(0, 16));
    if (bl_is_error(ret)) {
      close_sys(sd_num);
      throw new Error('bind() failed');
    }
    ret = listen_sys(new BigInt(0, sd_num), new BigInt(0, 1));
    if (bl_is_error(ret)) {
      close_sys(sd_num);
      throw new Error('listen() failed');
    }
    return sd_num;
  }

  // Read payload data from client socket
  function bl_read_payload_from_socket(client_sock, max_size) {
    var payload_buf = mem.malloc(max_size);
    var total_read = 0;
    while (total_read < max_size) {
      var remaining = max_size - total_read;
      var chunk_size = remaining < READ_CHUNK ? remaining : READ_CHUNK;
      var read_size = read_sys(new BigInt(0, client_sock), payload_buf.add(new BigInt(0, total_read)), new BigInt(0, chunk_size));
      if (bl_is_error(read_size)) {
        throw new Error('read() failed');
      }
      if (read_size.eq(0)) {
        break; // EOF
      }
      total_read += read_size.lo;

      // Progress update every 128KB
      if (total_read % (128 * 1024) === 0) {
        log('Received ' + total_read / 1024 + ' KB...');
      }
    }
    return {
      buf: payload_buf,
      size: total_read
    };
  }

  // Load and run payload from file
  function bl_load_from_file(path) {
    var skip_autoclose = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
    log('Loading payload from: ' + path);
    var payload = bl_read_file(path);
    if (payload === null) {
      error('Failed to read payload file');
      return false;
    }
    log('Read ' + payload.size + ' bytes');
    if (payload.size < 64) {
      error('ERROR: Payload too small');
      return false;
    }
    BinLoader.skip_autoclose = skip_autoclose;
    try {
      BinLoader.init(payload.buf, payload.size);
      if (!skip_autoclose) {
        log('Running payload in 1 second. Then auto close...');
        jsmaf.setTimeout(function () {
          BinLoader.run();
          log('Payload loaded successfully');
        }, 1000);
      } else {
        BinLoader.run();
        log('Payload loaded successfully');
      }
    } catch (e) {
      error('ERROR loading payload: ' + e.message);
      return false;
    }
    return true;
  }

  // send payload to elfldr
  function bl_send_to_elfldr(path, port) {
    var autoclose = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
    log('Sending payload "' + path + '" to elfldr on port ' + port);

    // Step 1: Read the payload from the specified file
    var payload = bl_read_file(path);
    if (payload === null) {
      error('Failed to read payload file');
      return false;
    }
    log('Read ' + payload.size + ' bytes of payload');
    if (payload.size < 64) {
      error('ERROR: Payload too small');
      return false;
    }

    // Step 2: Create a socket for communication
    var sd = socket(BL_AF_INET, BL_SOCK_STREAM, 0);
    var sd_num = sd instanceof BigInt ? sd.lo : sd;
    if (bl_is_error(sd)) {
      error('ERROR: socket() failed');
      return false;
    }

    // Step 3: Build sockaddr_in structure to specify the target host and port
    var sockaddr = mem.malloc(16);
    for (var j = 0; j < 16; j++) {
      mem.view(sockaddr).setUint8(j, 0);
    }
    mem.view(sockaddr).setUint8(1, 2); // AF_INET
    mem.view(sockaddr).setUint8(2, port >> 8 & 0xff); // port high byte
    mem.view(sockaddr).setUint8(3, port & 0xff); // port low byte
    mem.view(sockaddr).setUint32(4, 0, true); // INADDR_ANY

    // Step 4: Connect to the elfldr on the target IP (localhost)
    var ret = connect_sys(new BigInt(0, sd_num), sockaddr, new BigInt(0, 16));
    if (bl_is_error(ret)) {
      error('ERROR: connect() failed');
      close_sys(sd_num);
      return false;
    }
    log('Connected to elfldr');

    // Step 5: Send the payload to the elfldr via the socket
    var total_sent = 0;
    while (total_sent < payload.size) {
      var remaining = payload.size - total_sent;
      var chunk_size = remaining < READ_CHUNK ? remaining : READ_CHUNK;
      var bytes_sent = write_sys(new BigInt(0, sd_num), payload.buf.add(new BigInt(0, total_sent)), new BigInt(0, chunk_size));
      if (bl_is_error(bytes_sent)) {
        error('ERROR: write() failed');
        close_sys(sd_num);
        return false;
      }
      total_sent += bytes_sent.lo;

      // Progress update every 128KB
      if (total_sent % (128 * 1024) === 0) {
        log('Sent ' + total_sent / 1024 + ' KB...');
      }
    }
    log('Payload sent successfully, closing socket');

    // Step 6: Close the socket connection after sending the payload
    close_sys(sd_num);
    log('Connection closed');
    if (autoclose) {
      bl_autoclose(1000);
    }
    return true;
  }

  // Network binloader (fallback)
  function bl_network_loader() {
    log('Starting network payload server...');
    var server_sock;
    try {
      server_sock = bl_create_listen_socket(BIN_LOADER_PORT);
    } catch (e) {
      error('ERROR: ' + e.message);
      utils.notify('Bin loader failed!\n' + e.message);
      return false;
    }
    var network_str = '<PS4 IP>:' + BIN_LOADER_PORT;
    log('Listening on ' + network_str);
    log('Send your ELF payload to this address');
    utils.notify('Binloader listening on:\n' + network_str);

    // Accept client connection
    var sockaddr = mem.malloc(16);
    var sockaddr_len = mem.malloc(4);
    mem.view(sockaddr_len).setUint32(0, 16, true);
    var client_sock = accept_sys(new BigInt(0, server_sock), sockaddr, sockaddr_len);
    if (bl_is_error(client_sock)) {
      error('ERROR: accept() failed');
      close_sys(server_sock);
      return false;
    }
    var client_sock_num = client_sock instanceof BigInt ? client_sock.lo : client_sock;
    log('Client connected');
    var payload;
    try {
      payload = bl_read_payload_from_socket(client_sock_num, MAX_PAYLOAD_SIZE);
    } catch (e) {
      error('ERROR reading payload: ' + e.message);
      close_sys(client_sock_num);
      close_sys(server_sock);
      return false;
    }
    log('Received ' + payload.size + ' bytes total');
    close_sys(client_sock_num);
    close_sys(server_sock);
    if (payload.size < 64) {
      error('ERROR: Payload too small');
      return false;
    }
    BinLoader.skip_autoclose = false;
    try {
      BinLoader.init(payload.buf, payload.size);
      BinLoader.run();
      log('Payload loaded successfully');
    } catch (e) {
      error('ERROR loading payload: ' + e.message);
      return false;
    }
    return true;
  }

  // Main entry point with USB loader logic
  function bin_loader_main() {
    log('=== PS4 Payload Loader ===');

    // Priority 0 (PATCH-BROWSER): payload dari HTTP (goldhen.bin diambil main.js
    // via XHR sinkron SEBELUM exploit — setelah jailbreak browser sudah bisa
    // menjalankan payload lewat BinLoader dari buffer memori).
    if (typeof goldhenBuf !== 'undefined' && goldhenBuf !== null && goldhenBuf.byteLength > 0) {
      log('Found HTTP payload: ' + goldhenBuf.byteLength + ' bytes');
      var http_buf = mem.malloc(goldhenBuf.byteLength);
      var http_view = mem.view(http_buf);
      var http_u8 = new Uint8Array(goldhenBuf);
      for (var http_i = 0; http_i < http_u8.length; http_i++) {
        http_view.setUint8(http_i, http_u8[http_i]);
      }
      BinLoader.init(http_buf, goldhenBuf.byteLength);
      BinLoader.run();
      return;
    }

    // Priority 1: Check for USB payload on usb0-usb4 (like BD-JB does)
    for (var usb_path of USB_PAYLOAD_PATHS) {
      var usb_size = bl_file_exists(usb_path);
      if (usb_size > 0) {
        log('Found USB payload: ' + usb_path + ' (' + usb_size + ' bytes)');
        utils.notify('USB payload found!\nCopying to /data...');

        // Copy USB payload to /data for future use
        if (bl_copy_file(usb_path, DATA_PAYLOAD_PATH)) {
          log('Copied to ' + DATA_PAYLOAD_PATH);
        } else {
          log('Warning: Failed to copy to /data, running from USB');
        }

        // Load from USB
        return bl_load_from_file(usb_path, false);
      }
    }

    // Priority 2: Check for cached /data payload
    var data_size = bl_file_exists(DATA_PAYLOAD_PATH);
    if (data_size > 0) {
      log('Found cached payload: ' + DATA_PAYLOAD_PATH + ' (' + data_size + ' bytes)');
      return bl_load_from_file(DATA_PAYLOAD_PATH, false);
    }

    // Priority 3: Check for cached SANDBOX payload
    var sandbox_size = bl_file_exists(SANDBOX_PAYLOAD_PATH);
    if (sandbox_size > 0) {
      log('Found cached payload: ' + SANDBOX_PAYLOAD_PATH + ' (' + sandbox_size + ' bytes)');
      return bl_load_from_file(SANDBOX_PAYLOAD_PATH, false);
    }

    // Priority 4: Fall back to network loader
    error('No payload file found, starting network loader');
    utils.notify('No payload found.\nStarting network loader...');
    return bl_network_loader();
  }
  function bl_is_port_listening_localhost(port) {
    var SO_SNDTIMEO = 0x1005;
    var SO_RCVTIMEO = 0x1006;
    var sd = socket(BL_AF_INET, BL_SOCK_STREAM, 0);
    if (bl_is_error(sd)) return false;
    var sd_num = sd instanceof BigInt ? sd.lo : sd;
    try {
      var tv = mem.malloc(16);
      mem.view(tv).setBigInt(0, new BigInt(0, 0), true);
      mem.view(tv).setBigInt(8, new BigInt(0, 200000), true);
      setsockopt(sd_num, BL_SOL_SOCKET, SO_SNDTIMEO, tv, 16);
      setsockopt(sd_num, BL_SOL_SOCKET, SO_RCVTIMEO, tv, 16);
      var sockaddr = mem.malloc(16);
      for (var j = 0; j < 16; j++) mem.view(sockaddr).setUint8(j, 0);
      mem.view(sockaddr).setUint8(1, 2);
      mem.view(sockaddr).setUint8(2, port >> 8 & 0xff);
      mem.view(sockaddr).setUint8(3, port & 0xff);
      mem.view(sockaddr).setUint8(4, 127);
      mem.view(sockaddr).setUint8(5, 0);
      mem.view(sockaddr).setUint8(6, 0);
      mem.view(sockaddr).setUint8(7, 1);
      var ret = connect_sys(new BigInt(0, sd_num), sockaddr, new BigInt(0, 16));
      return !bl_is_error(ret) && ret.eq(0);
    } finally {
      close_sys(sd_num);
    }
  }

  // End of binloader_init() function
  // Call bin_loader_main() to start binloader

  function bl_init_elfldr() {
    if (bl_is_port_listening_localhost(9021)) {
      log('9021 already listening, skip /download0/elfldr.elf');
      jsmaf.setTimeout(function () {
        bl_autoclose(500);
      }, 500);
    } else {
      bl_load_from_file('/download0/elfldr.elf', false);
    }
  }
  if (payloadSelect === 'payload.bin' || payloadSelect === undefined) {
    bin_loader_main();
  } else if (payloadSelect === 'elfldr.elf') {
    bl_init_elfldr();
  } else {
    if (bl_is_port_listening_localhost(9021)) {
      bl_send_to_elfldr('/download0/' + payloadSelect, 9021);
    } else if (bl_is_port_listening_localhost(9090)) {
      bl_send_to_elfldr('/download0/' + payloadSelect, 9090);
    } else {
      var ret = bl_load_from_file('/download0/elfldr.elf', true);
      if (ret) {
        log('Sending "' + payloadSelect + '" in 1 second');
        jsmaf.setTimeout(function () {
          bl_send_to_elfldr('/download0/' + payloadSelect, 9021);
        }, 1000);
      }
    }
  }
  return {
    bl_load_from_file,
    bl_network_loader
  };
}

// Verify function is defined
if (typeof binloader_init === 'function') {
  debug('binloader.js loaded - binloader_init() function ready');
} else {
  error('ERROR: binloader_init function not defined!');
}