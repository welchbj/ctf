'use strict';
/** @type {!Array} */
var _0x1e80 = ["bGVuZ3Ro", "ZnJvbUNoYXJDb2Rl", "c3Vic3Ry", "bWFw", "Y2hhckNvZGVBdA==", "YXBwbHk=", "ZnVuY3Rpb24gKlwoICpcKQ==", "XCtcKyAqKD86XzB4KD86W2EtZjAtOV0pezQsNn18KD86XGJ8XGQpW2EtejAtOV17MSw0fSg/OlxifFxkKSk=", "aW5pdA==", "dGVzdA==", "Y2hhaW4=", "e30uY29uc3RydWN0b3IoInJldHVybiB0aGlzIikoICk=", "Y29uc29sZQ==", "ZGVidWc=", "aW5mbw==", "ZXhjZXB0aW9u", "bG9n", "d2Fybg==", "ZXJyb3I=", "dHJhbnNhY3Rpb24=", "YmxvY2tz", "cmVhZG9ubHk=", "Y291bnQ=", "b25zdWNjZXNz", "cmVzdWx0", "cmVhZHdyaXRl", "Y2xlYXI=", 
"cmV3YXJkcw==", "b2JqZWN0U3RvcmU=", "YWRk", "cmV3YXJk", "d2t2cHo=", "c3RyaW5naWZ5", "cGFkRW5k", "X21hbGxvYw==", "d3JpdGVBcnJheVRvTWVtb3J5", "d3JpdGVBc2NpaVRvTWVtb3J5", "dGNyeXB0", "Ym9vbGVhbg==", "bnVtYmVy", "c2xpY2U=", "ZnJvbQ==", "anNvbg==", "dGhlbg==", "Z29vZA==", "ZmxhZw==", "c3RyaW5n", "Y291bnRlcg==", "Y29uc3RydWN0b3I=", "Y2FsbA==", "YWN0aW9u", "Z2dlcg==", "c3RhdGVPYmplY3Q="];
/**
 * @param {string} k
 * @param {?} init_using_data
 * @return {?}
 */
var _0x26be = function(k, init_using_data) {
  /** @type {number} */
  k = k - 0;
  var text = _0x1e80[k];
  if (_0x26be["qLftMO"] === undefined) {
    (function() {
      /**
       * @return {?}
       */
      var unescape = function() {
        var source;
        try {
          source = Function("return (function() " + '{}.constructor("return this")( )' + ");")();
        } catch (_0x196651) {
          /** @type {!Window} */
          source = window;
        }
        return source;
      };
      var s_utf8 = unescape();
      /** @type {string} */
      var listeners = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
      if (!s_utf8["atob"]) {
        /**
         * @param {?} i
         * @return {?}
         */
        s_utf8["atob"] = function(i) {
          var str = String(i)["replace"](/=+$/, "");
          /** @type {number} */
          var bc = 0;
          var bs;
          var buffer;
          /** @type {number} */
          var Y = 0;
          /** @type {string} */
          var pix_color = "";
          for (; buffer = str["charAt"](Y++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? pix_color = pix_color + String["fromCharCode"](255 & bs >> (-2 * bc & 6)) : 0) {
            buffer = listeners["indexOf"](buffer);
          }
          return pix_color;
        };
      }
    })();
    /**
     * @param {?} dataString
     * @return {?}
     */
    _0x26be["yMxSxC"] = function(dataString) {
      /** @type {string} */
      var data = atob(dataString);
      /** @type {!Array} */
      var escapedString = [];
      /** @type {number} */
      var val = 0;
      var key = data["length"];
      for (; val < key; val++) {
        escapedString = escapedString + ("%" + ("00" + data["charCodeAt"](val)["toString"](16))["slice"](-2));
      }
      return decodeURIComponent(escapedString);
    };
    _0x26be["jnfimM"] = {};
    /** @type {boolean} */
    _0x26be["qLftMO"] = !![];
  }
  var b = _0x26be["jnfimM"][k];
  if (b === undefined) {
    text = _0x26be["yMxSxC"](text);
    _0x26be["jnfimM"][k] = text;
  } else {
    text = b;
  }
  return text;
};
let _0x3e8c22 = function(InkElement) {
  let _0x1b07b0 = "";
  for (let el = 0; el < InkElement[_0x26be("0x0")]; el = el + 2) {
    _0x1b07b0 = _0x1b07b0 + String[_0x26be("0x1")](parseInt(InkElement[_0x26be("0x2")](el, 2), 16));
  }
  return _0x1b07b0;
};
let _0x1756db = function(data, point) {
  return Array["from"](data)[_0x26be("0x3")](function(isSlidingUp, diff) {
    return isSlidingUp[_0x26be("0x4")](0) ^ point["charCodeAt"](diff % point["length"]);
  });
};
let _0x433113 = function(addDocObjectToDocMap) {
  var gotoNewOfflinePage = function() {
    /** @type {boolean} */
    var closeExpr = !![];
    return function(value, deferred) {
      /** @type {!Function} */
      var closingExpr = closeExpr ? function() {
        if (deferred) {
          var mom = deferred[_0x26be("0x5")](value, arguments);
          /** @type {null} */
          deferred = null;
          return mom;
        }
      } : function() {
      };
      /** @type {boolean} */
      closeExpr = ![];
      return closingExpr;
    };
  }();
  (function() {
    gotoNewOfflinePage(this, function() {
      /** @type {!RegExp} */
      var URI = new RegExp(_0x26be("0x6"));
      /** @type {!RegExp} */
      var inlineAttributeCommentRegex = new RegExp(_0x26be("0x7"), "i");
      var string = _0x3f4022(_0x26be("0x8"));
      if (!URI[_0x26be("0x9")](string + _0x26be("0xa")) || !inlineAttributeCommentRegex[_0x26be("0x9")](string + "input")) {
        string("0");
      } else {
        _0x3f4022();
      }
    })();
  })();
  var getAlignItem = function() {
    /** @type {boolean} */
    var closeExpr = !![];
    return function(value, deferred) {
      /** @type {!Function} */
      var closingExpr = closeExpr ? function() {
        if (deferred) {
          var mom = deferred[_0x26be("0x5")](value, arguments);
          /** @type {null} */
          deferred = null;
          return mom;
        }
      } : function() {
      };
      /** @type {boolean} */
      closeExpr = ![];
      return closingExpr;
    };
  }();
  var alignContentAlignItem = getAlignItem(this, function() {
    /**
     * @return {undefined}
     */
    var frameData = function() {
    };
    /**
     * @return {?}
     */
    var unescape = function() {
      var source;
      try {
        source = Function("return (function() " + _0x26be("0xb") + ");")();
      } catch (_0x45f866) {
        /** @type {!Window} */
        source = window;
      }
      return source;
    };
    var s_utf8 = unescape();
    if (!s_utf8[_0x26be("0xc")]) {
      s_utf8[_0x26be("0xc")] = function(frameData) {
        var response = {};
        /** @type {function(): undefined} */
        response["log"] = frameData;
        /** @type {function(): undefined} */
        response["warn"] = frameData;
        /** @type {function(): undefined} */
        response[_0x26be("0xd")] = frameData;
        /** @type {function(): undefined} */
        response[_0x26be("0xe")] = frameData;
        /** @type {function(): undefined} */
        response["error"] = frameData;
        /** @type {function(): undefined} */
        response[_0x26be("0xf")] = frameData;
        /** @type {function(): undefined} */
        response["trace"] = frameData;
        return response;
      }(frameData);
    } else {
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0x10")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0x11")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0xd")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0xe")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0x12")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")][_0x26be("0xf")] = frameData;
      /** @type {function(): undefined} */
      s_utf8[_0x26be("0xc")]["trace"] = frameData;
    }
  });
  alignContentAlignItem();
  let trans = db[_0x26be("0x13")]([_0x26be("0x14")], _0x26be("0x15"));
  let _0x22552d = trans["objectStore"](_0x26be("0x14"));
  let curTagData = _0x22552d[_0x26be("0x16")]();
  /**
   * @return {undefined}
   */
  curTagData[_0x26be("0x17")] = function() {
    addDocObjectToDocMap(curTagData[_0x26be("0x18")]);
  };
};
let _0x443099 = function(canCreateDiscussions) {
  let trans = db[_0x26be("0x13")](["blocks"], _0x26be("0x19"));
  let _0x5cc2ae = trans["objectStore"](_0x26be("0x14"));
  let _0x3782b8 = _0x5cc2ae[_0x26be("0x1a")]();
};
setInterval(function() {
  _0x3f4022();
}, 4E3);
let _0x1e4498 = function(mess) {
  let _0x56cc9e = db[_0x26be("0x13")](_0x26be("0x1b"), _0x26be("0x19"));
  let _0xf0202e = _0x56cc9e[_0x26be("0x1c")]("rewards");
  _0xf0202e[_0x26be("0x1d")]({
    "flag" : _0x1756db(mess, _0x26be("0x1e"))
  });
};
console[_0x26be("0x10")]("starting");
_0x433113(function(canCreateDiscussions) {
  let arr = _0x1756db(_0x3e8c22(deploy_key), _0x26be("0x1f"));
  console[_0x26be("0x10")](arr);
  let data = {
    "blocks_mined" : canCreateDiscussions
  };
  let args = JSON[_0x26be("0x20")](data);
  args = args[_0x26be("0x21")](args[_0x26be("0x0")] + (8 - args[_0x26be("0x0")] % 8), " ");
  console[_0x26be("0x10")](args);
  let sql = Module[_0x26be("0x22")](args["length"] + 1);
  let filename = Module[_0x26be("0x22")](arr[_0x26be("0x0")] + 1);
  Module[_0x26be("0x23")](arr, filename);
  Module[_0x26be("0x24")](args, sql);
  Module["ccall"](_0x26be("0x25"), _0x26be("0x26"), [_0x26be("0x27"), "number", _0x26be("0x27")], [filename, sql, args[_0x26be("0x0")]]);
  let potentialElements = new Uint8Array(Module["HEAP8"][_0x26be("0x28")](sql, sql + args[_0x26be("0x0")]));
  let _0x32e2fa = fetch("/c2/reward", {
    "method" : "POST",
    "body" : JSON["stringify"](Array[_0x26be("0x29")](potentialElements))
  })["then"]((canCreateDiscussions) => {
    return canCreateDiscussions[_0x26be("0x2a")]();
  })[_0x26be("0x2b")]((canCreateDiscussions) => {
    if (canCreateDiscussions[_0x26be("0x2c")]) {
      _0x1e4498(canCreateDiscussions[_0x26be("0x2d")]);
      _0x443099();
    }
  });
});
/**
 * @param {?} canCreateDiscussions
 * @return {?}
 */
function _0x3f4022(canCreateDiscussions) {
  /**
   * @param {number} i
   * @return {?}
   */
  function add(i) {
    if (typeof i === _0x26be("0x2e")) {
      return function(canCreateDiscussions) {
      }["constructor"]("while (true) {}")[_0x26be("0x5")](_0x26be("0x2f"));
    } else {
      if (("" + i / i)["length"] !== 1 || i % 20 === 0) {
        (function() {
          return !![];
        })[_0x26be("0x30")]("debu" + "gger")[_0x26be("0x31")](_0x26be("0x32"));
      } else {
        (function() {
          return ![];
        })[_0x26be("0x30")]("debu" + _0x26be("0x33"))[_0x26be("0x5")](_0x26be("0x34"));
      }
    }
    add(++i);
  }
  try {
    if (canCreateDiscussions) {
      return add;
    } else {
      add(0);
    }
  } catch (_0x1ad9e0) {
  }
}
;