// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: Unlicense

const validate = require('../');
const test = require('tape');
const fs = require('fs');
const path = require('path');
const Log = require('async-append-only-log');
const generateFixture = require('ssb-fixtures');
const rimraf = require('rimraf');
const mkdirp = require('mkdirp');
const JITDB = require('jitdb');
const {query, fromDB, toCallback} = require('jitdb/operators');
const copy = require('jitdb/copy-json-to-bipf-async');

// define directory and paths
const dir = '/tmp/validate-test';
const oldLogPath = path.join(dir, 'flume', 'log.offset');
const newLogPath = path.join(dir, 'flume', 'log.bipf');
const indexesDir = path.join(dir, 'indexes');

// generate fixture
rimraf.sync(dir, {maxBusyTries: 3});
mkdirp.sync(dir);

const SEED = 'sloop';
const MESSAGES = 5;
const AUTHORS = 1;

const validMsg = {
  previous: '%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256',
  author: '@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519',
  sequence: 8,
  timestamp: 1470187438539,
  hash: 'sha256',
  content: {
    type: 'contact',
    contact: '@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519',
    following: true,
    blocking: false,
  },
  signature:
    'PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519',
};

const hmacMsg = {
  previous: null,
  sequence: 1,
  author: '@EnPSnV1HZdyE7pcKxqukyhmnwE9076RtAlYclaUMX5g=.ed25519',
  timestamp: 1624360181359,
  hash: 'sha256',
  content: {type: 'example'},
  signature:
    'w670wqnD1A5blFaYxDiIhPOTwz8I7syVx30jac1feQK/OywHFfrcLVw2S1KmxK9GzWxvKxLMle/jKjf2+pHtAg==.sig.ed25519',
};

const hmacKey1 = null;
const hmacKey2 = 'CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U=';

test('generate fixture with flumelog-offset', (t) => {
  generateFixture({
    outputDir: dir,
    seed: SEED,
    messages: MESSAGES,
    authors: AUTHORS,
    slim: false,
  }).then(() => {
    t.true(fs.existsSync(oldLogPath), 'log.offset was created');
    t.end();
  });
});

test('move flumelog-offset to async-log', (t) => {
  copy(oldLogPath, newLogPath, (err) => {
    if (err) t.fail(err);
    setTimeout(() => {
      t.true(fs.existsSync(newLogPath), 'log.bipf was created');
      t.end();
    }, 4000);
  });
});

let raf;
let db;

test('core indexes', (t) => {
  raf = Log(newLogPath, {blockSize: 64 * 1024});
  rimraf.sync(indexesDir);
  db = JITDB(raf, indexesDir);
  db.onReady(() => {
    t.pass(`database ready`);
    t.end();
  });
});

test('batch verification of message signatures', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        // map msgs to msg.value for each
        const msgs = kvtMsgs.map((msg) => msg.value);
        // attempt verification of all messages
        validate.verifySignatures(hmacKey1, msgs, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('batch verification of out-of-order message signatures', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // shuffle the messages (generate out-of-order state)
        msgs.sort(() => Math.random() - 0.5);
        // attempt verification of all messages
        validate.verifySignatures(hmacKey1, msgs, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('verification of single message signature (valid)', (t) => {
  let msgs = [validMsg];
  validate.verifySignatures(hmacKey1, msgs, (err, res) => {
    t.equal(err, null, 'success: err is null');
    t.deepEqual(
      res,
      ['%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256'],
      'success: returned key is correct',
    );
    t.end();
  });
});

test('verification of single message signature (invalid)', (t) => {
  let invalidMsg = validMsg;
  invalidMsg.content.following = false;
  let msgs = [invalidMsg];
  validate.verifySignatures(hmacKey1, msgs, (err, res) => {
    t.match(
      err.message,
      /Signature was invalid/,
      'found invalid message: Signature was invalid',
    );
    t.end();
  });
});

test('verification of single message signature with hmac', (t) => {
  let msgs = [hmacMsg];
  validate.verifySignatures(hmacKey2, msgs, (err, res) => {
    t.equal(err, null, 'success: err is null');
    t.deepEqual(
      res,
      ['%8RL6pJ+3zdcX4v9wv3inbWzlnQH7ZV4Hi0Nvzdfibu0=.sha256'],
      'success: returned key is correct',
    );
    t.pass(`validated ${MESSAGES} messages`);
    t.end();
  });
});

test('verification with integer as msgs input (should be array of objects)', (t) => {
  let msgs = 3;
  validate.verifySignatures(hmacKey2, msgs, (err, res) => {
    t.match(
      err.message,
      /input must be an array of message objects/,
      'input must be an array of message objects',
    );
    t.end();
  });
});

test('validation of first message (`seq` == 1) without `previous`', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) return t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // attempt validation of single message (assume `previous` is null)
        validate.validateSingle(hmacKey1, msgs[0], null, (err, res) => {
          t.equal(err, null, 'success: err is null');
          // maybe we can check the key here somehow? (res) is-canonical-base64 maybe?
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('validation of a single message with `previous`', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) return t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // attempt validation of single message (include previous message)
        validate.validateSingle(hmacKey1, msgs[1], msgs[0], (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('validation of a single message (`seq` > 1) without `previous`', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) return t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // attempt validation of a single message without `previous`
        msgs[3].previous = null // just to force the check for `seq`
        validate.validateSingle(hmacKey1, msgs[3], null, (err, res) => {
          t.match(
            err.message,
            /The first message of a feed must have seq of 1/,
            'found invalid message: The first message of a feed must have seq of 1',
          );
          t.end();
        });
      }),
    );
  });
});

test('validation of a single message with hmac (without `previous`)', (t) => {
  validate.validateSingle(hmacKey2, hmacMsg, null, (err, res) => {
    t.equal(err, null, 'success: err is null');
    t.equal(
      res,
      '%8RL6pJ+3zdcX4v9wv3inbWzlnQH7ZV4Hi0Nvzdfibu0=.sha256',
      'success: returned key is correct',
    );
    t.pass(`validated ${MESSAGES} messages`);
    t.end();
  });
});

test('validation of a single message with hmac as buffer (without `previous`)', (t) => {
  let hmacBuf = Buffer.from(
    'CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U',
    'base64',
  );
  validate.validateSingle(hmacBuf, hmacMsg, null, (err, res) => {
    t.equal(err, null, 'success: err is null');
    t.equal(
      res,
      '%8RL6pJ+3zdcX4v9wv3inbWzlnQH7ZV4Hi0Nvzdfibu0=.sha256',
      'success: returned key is correct',
    );
    t.pass(`validated ${MESSAGES} messages`);
    t.end();
  });
});

test("validation of a single hmac'd message without hmac key", (t) => {
  validate.validateSingle(hmacKey1, hmacMsg, null, (err, res) => {
    t.match(
      err.message,
      /Signature was invalid/,
      'found invalid message: Signature was invalid',
    );
    t.end();
  });
});

test("validation of a single hmac'd message with invalid hmac key", (t) => {
  validate.validateSingle('isnotvalid', hmacMsg, null, (err, res) => {
    t.match(
      err.message,
      /string must be base64 encoded/,
      'hmac key invalid: string must be base64 encoded',
    );
    t.end();
  });
});

test('batch validation of full feed', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // attempt validation of all messages (assume `previous` is null)
        validate.validateBatch(hmacKey1, msgs, null, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('batch validation of partial feed (previous seq == 1)', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // shift first msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages
        validate.validateBatch(hmacKey1, msgs, previous, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('batch validation of partial feed (previous seq > 1)', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // skip first msg in the array
        first = msgs.shift();
        // shift second msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages
        validate.validateBatch(hmacKey1, msgs, previous, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});

test('batch validation of partial feed without `previous`', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // shift first msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages without `previous`
        msgs[0].previous = null // just to force the check for `seq`
        validate.validateBatch(hmacKey1, msgs, null, (err, res) => {
          t.match(
            err.message,
            /The first message of a feed must have seq of 1/,
            'found invalid message: The first message of a feed must have seq of 1',
          );
          t.end();
        });
      }),
    );
  });
});

test('batch validation of out-of-order messages', (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        const msgs = kvtMsgs.map((msg) => msg.value);
        // shuffle the messages (generate out-of-order state)
        msgs.sort(() => Math.random() - 0.5);
        // attempt validation of all messages
        validate.validateOOOBatch(hmacKey1, msgs, (err, res) => {
          t.equal(err, null, 'success: err is null');
          t.pass(`validated ${MESSAGES} messages`);
          t.end();
        });
      }),
    );
  });
});
