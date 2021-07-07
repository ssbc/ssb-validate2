const v = require('ssb-validate');

const convertError = (err) => {
  if (!err.message) return err;
  if (err.message.includes('invalid signature')) {
    err.message = 'Signature was invalid';
  } else if (err.message.includes('initial message must have sequence: 1,')) {
    err.message = 'The first message of a feed must have seq of 1';
  } else if (err.message.includes('invalid HMAC key')) {
    err.message = 'string must be base64 encoded';
  }
  return err;
};

const verifySignatures = (hmacKey, msgVals, cb) => {
  if (!Array.isArray(msgVals)) {
    cb(new Error('input must be an array of message objects'));
    return;
  }
  for (const msgVal of msgVals) {
    const err = v.checkInvalidOOO(msgVal, hmacKey);
    if (err) {
      cb(convertError(err));
      return;
    }
  }
  const keys = msgVals.map(v.id);
  cb(null, keys);
};

const validateSingle = (hmacKey, msgVal, previous, cb) => {
  validateBatch(hmacKey, [msgVal], previous, (err, keys) => {
    if (err) cb(err);
    else cb(err, keys[0]);
  });
};

const validateBatch = (hmacKey, msgVals, previous, cb) => {
  if (!Array.isArray(msgVals)) {
    cb(new Error('input must be an array of message objects'));
    return;
  }
  let state = v.initial();
  try {
    if (previous) {
      const previousKVT = v.toKeyValueTimestamp(previous);
      state = {
        validated: 1,
        queued: 0,
        queue: [previousKVT],
        feeds: {
          [previous.author]: {
            id: previousKVT.key,
            sequence: previous.sequence,
            timestamp: previousKVT.timestamp,
            queue: [],
          },
        },
      };
    }
    for (const msgVal of msgVals) {
      state = v.append(state, hmacKey, msgVal);
      if (state.error) {
        cb(convertError(state.error));
        return;
      }
    }
  } catch (err) {
    cb(convertError(err));
    return;
  }
  const keys = msgVals.map(v.id);
  cb(null, keys);
};

const validateOOOBatch = (hmacKey, msgVals, cb) => {
  verifySignatures(hmacKey, msgVals, cb);
};

const validateMultiAuthorBatch = (hmacKey, msgVals, cb) => {
  verifySignatures(hmacKey, msgVals, cb);
};

// Mirrors the `ready` function for the `web` version of `ssb-validate2-rsjs`.
// The function initializes WASM and WebWorkers in `web`. We define it here with
// a callback so that both libraries can be safely called with the same code.
const ready = (cb) => {
  cb();
};

module.exports.ready = ready;
module.exports.verifySignatures = verifySignatures;
module.exports.validateSingle = validateSingle;
module.exports.validateBatch = validateBatch;
module.exports.validateOOOBatch = validateOOOBatch;
module.exports.validateMultiAuthorBatch = validateMultiAuthorBatch;
