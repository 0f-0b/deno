// deno-fmt-ignore-file
// deno-lint-ignore-file

// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// Taken from Node 23.9.0
// This file is automatically generated by `tests/node_compat/runner/setup.ts`. Do not modify this file manually.

'use strict';
const common = require('../common');
const { Writable } = require('stream');

const assert = require('assert');
const http = require('http');

// Check if Writable.toWeb works on the response object after creating a server.
const server = http.createServer(
  common.mustCall((req, res) => {
    const webStreamResponse = Writable.toWeb(res);
    assert.strictEqual(webStreamResponse instanceof WritableStream, true);
    res.end();
  })
);

server.listen(
  0,
  common.mustCall(() => {
    http.get(
      {
        port: server.address().port,
      },
      common.mustCall(() => {
        server.close();
      })
    );
  })
);
