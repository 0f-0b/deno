// deno-fmt-ignore-file
// deno-lint-ignore-file

// Copyright Joyent and Node contributors. All rights reserved. MIT license.
// Taken from Node 23.9.0
// This file is automatically generated by `tests/node_compat/runner/setup.ts`. Do not modify this file manually.

'use strict';
require('../common');
const vm = require('vm');

// Check that we do not accidentally query attributes.
// Issue: https://github.com/nodejs/node/issues/11902
const handler = {
  getOwnPropertyDescriptor: (target, prop) => {
    throw new Error('whoops');
  }
};
const sandbox = new Proxy({ foo: 'bar' }, handler);
const context = vm.createContext(sandbox);

vm.runInContext('', context);
