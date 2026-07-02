'use strict';

// Lightweight state (de)serializer used by the "import configuration" and
// "restore session" features. Function-typed values are preserved across the
// wire by tagging them with a marker and rehydrating them on the way back in.
//
// This mirrors the classic node-serialize behaviour: tagged values are revived
// with eval(), and an immediately-invoked function expression will therefore
// execute during the revive step.
const FUNCFLAG = '_$$ND_FUNC$$_';

function serialize(obj) {
  return JSON.stringify(obj, function (key, value) {
    if (typeof value === 'function') {
      return FUNCFLAG + value.toString();
    }
    return value;
  });
}

function unserialize(str) {
  return JSON.parse(str, function (key, value) {
    if (typeof value !== 'string' || value.indexOf(FUNCFLAG) !== 0) {
      return value;
    }
    const src = value.substring(FUNCFLAG.length);
    // eslint-disable-next-line no-eval
    return eval('(' + src + ')');
  });
}

module.exports = { serialize, unserialize, FUNCFLAG };
