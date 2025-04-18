// deno-fmt-ignore-file
// deno-lint-ignore-file

// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// Taken from Node 23.9.0
// This file is automatically generated by `tests/node_compat/runner/setup.ts`. Do not modify this file manually.

'use strict';

const common = require('../common');
const stream = require('stream');

function testPushArg(val) {
  const readable = new stream.Readable({
    read: () => {}
  });
  readable.on('error', common.expectsError({
    code: 'ERR_INVALID_ARG_TYPE',
    name: 'TypeError'
  }));
  readable.push(val);
}

testPushArg([]);
testPushArg({});
testPushArg(0);

function testUnshiftArg(val) {
  const readable = new stream.Readable({
    read: () => {}
  });
  readable.on('error', common.expectsError({
    code: 'ERR_INVALID_ARG_TYPE',
    name: 'TypeError'
  }));
  readable.unshift(val);
}

testUnshiftArg([]);
testUnshiftArg({});
testUnshiftArg(0);
