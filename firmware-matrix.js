(function (global) {
  "use strict";

  var legacyChains = {
    "6.72": 2,
    "7.00": 1, "7.01": 1, "7.02": 1,
    "7.50": 1, "7.51": 1, "7.55": 1,
    "8.00": 1, "8.01": 1, "8.03": 1,
    "8.50": 1, "8.52": 1,
    "9.00": 1, "9.03": 1, "9.04": 1,
    "9.50": 1, "9.51": 1, "9.60": 1,
    "10.00": 4, "10.01": 4,
    "10.50": 4, "10.70": 4, "10.71": 4,
    "11.00": 4, "11.02": 4
  };
  var poopsFirmwares = {
    "11.50": true, "11.52": true,
    "12.00": true, "12.02": true,
    "12.50": true, "12.52": true,
    "13.00": true,
    "13.02": true, "13.04": true,
    "13.50": true, "13.52": true
  };

  function detect(userAgent) {
    var match = (userAgent || "").match(/PlayStation\s+4[\/ ](\d+\.\d+)/i);
    return match ? match[1] : null;
  }

  function select(firmware) {
    if (Object.prototype.hasOwnProperty.call(legacyChains, firmware)) {
      return { backend: "legacy", chain: legacyChains[firmware] };
    }
    if (poopsFirmwares[firmware]) return { backend: "poops", chain: null };
    return { backend: "unsupported", chain: null };
  }

  global.ADMIRAL_MATRIX = {
    detect: detect,
    select: select,
    legacyChains: legacyChains,
    poopsFirmwares: poopsFirmwares
  };
})(window);
