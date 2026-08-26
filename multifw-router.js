(function () {
  "use strict";

  var ua = navigator.userAgent || "";
  var matrix = window.ADMIRAL_MATRIX;
  var firmware = matrix.detect(ua);
  var stateEl = document.getElementById("state");
  var spinEl = document.getElementById("spin");

  function stop(message) {
    stateEl.textContent = message;
    stateEl.className = "bad";
    spinEl.style.display = "none";
  }

  if (!firmware) {
    stop("open this page in the PS4 browser");
    return;
  }

  window.ADMIRAL_FIRMWARE = firmware;
  var route = matrix.select(firmware);

  if (route.backend === "legacy") {
    stateEl.textContent = "selecting firmware toolchain...";
    localStorage.setItem("exploitChain", String(route.chain));
    localStorage.setItem("bareboneJB", "true");
    sessionStorage.setItem("payload_path", "../payload.bin");
    location.replace("legacy/exploit");
    return;
  }

  if (route.backend === "poops") {
    stateEl.textContent = "loading Poops chain for " + firmware + "...";
    var script = document.createElement("script");
    script.type = "module";
    script.src = "chain_poops.js";
    script.onerror = function () { stop("failed to load Poops chain"); };
    document.body.appendChild(script);
    return;
  }

  if (firmware === "12.70") {
    stop("12.70 detected - no validated PS4 GoldHEN browser chain in this build");
    return;
  }

  stop("firmware " + firmware + " is not supported by the available offsets");
})();
