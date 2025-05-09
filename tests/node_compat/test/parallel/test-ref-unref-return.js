// deno-fmt-ignore-file
// deno-lint-ignore-file

// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// Taken from Node 23.9.0
// This file is automatically generated by `tests/node_compat/runner/setup.ts`. Do not modify this file manually.

'use strict';
require('../common');
const assert = require('assert');
const net = require('net');
const dgram = require('dgram');

assert.ok((new net.Server()).ref() instanceof net.Server);
assert.ok((new net.Server()).unref() instanceof net.Server);
assert.ok((new net.Socket()).ref() instanceof net.Socket);
assert.ok((new net.Socket()).unref() instanceof net.Socket);
assert.ok((new dgram.Socket('udp4')).ref() instanceof dgram.Socket);
assert.ok((new dgram.Socket('udp6')).unref() instanceof dgram.Socket);
