// Copyright 2018-2026 the Deno authors. MIT license.

// @ts-check

import { core, primordials } from "ext:core/mod.js";
const {
  FunctionPrototypeApply,
  ObjectPrototypeIsPrototypeOf,
  SafeFinalizationRegistry,
  SafeSet,
  SafeWeakMap,
  SafeWeakRef,
  Symbol,
  SymbolFor,
  TypeError,
} = primordials;

import * as webidl from "ext:deno_webidl/00_webidl.js";
import { createFilteredInspectProxy } from "./01_console.js";
import {
  defineEventHandler,
  Event,
  EventTarget,
  listenerCount,
  setIsTrusted,
} from "./02_event.js";
import { clearTimeout, refTimer, unrefTimer } from "./02_timers.js";

// Since WeakSet is not a iterable, WeakRefSet class is provided to store and
// iterate objects.
// To create an AsyncIterable using GeneratorFunction in the internal code,
// there are many primordial considerations, so we simply implement the
// each method.
class WeakRefSet {
  #refs = new SafeSet();
  #valueToRef = new SafeWeakMap();
  #finalizer = new SafeFinalizationRegistry((ref) => this.#refs.delete(ref));

  add(value) {
    if (!this.#valueToRef.has(value)) {
      const ref = new SafeWeakRef(value);
      this.#refs.add(ref);
      this.#valueToRef.set(value, ref);
      this.#finalizer.register(value, ref, ref);
    }
  }

  delete(value) {
    const ref = this.#valueToRef.get(value);
    if (ref !== undefined) {
      this.#refs.delete(ref);
      this.#valueToRef.delete(value);
      this.#finalizer.unregister(ref);
    }
  }

  each(fn) {
    // deno-lint-ignore prefer-primordials
    for (const ref of this.#refs) {
      const value = ref.deref();
      if (value === undefined) {
        this.#refs.delete(ref);
        this.#finalizer.unregister(ref);
      } else {
        fn(value);
      }
    }
  }
}

const add = Symbol("[[add]]");
const signalAbort = Symbol("[[signalAbort]]");
const remove = Symbol("[[remove]]");
const runAbortSteps = Symbol("[[runAbortSteps]]");
const abortReason = Symbol("[[abortReason]]");
const abortAlgos = Symbol("[[abortAlgos]]");
const timerId = Symbol("[[timerId]]");
const sourceSignals = Symbol("[[sourceSignals]]");
const dependentSignals = Symbol("[[dependentSignals]]");
const activeDependents = Symbol("[[activeDependents]]");
const signal = Symbol("[[signal]]");

function refSignal(signal) {
  if (signal[timerId] !== null) {
    refTimer(signal[timerId]);
  } else if (signal[sourceSignals]) {
    signal[sourceSignals].each((sourceSignal) => {
      sourceSignal[activeDependents] ??= new SafeSet();
      sourceSignal[activeDependents].add(signal);
      refSignal(sourceSignal);
    });
  }
}

function tryUnrefSignal(signal) {
  if (
    listenerCount(signal, "abort") > 0 ||
    (signal[abortAlgos] && signal[abortAlgos].size > 0) ||
    (signal[activeDependents] && signal[activeDependents].size > 0)
  ) {
    return;
  }
  if (signal[timerId] !== null) {
    unrefTimer(signal[timerId]);
  } else if (signal[sourceSignals]) {
    signal[sourceSignals].each((sourceSignal) => {
      if (sourceSignal[activeDependents]?.delete(signal)) {
        tryUnrefSignal(sourceSignal);
      }
    });
  }
}

const illegalConstructorKey = Symbol("illegalConstructorKey");

class AbortSignal extends EventTarget {
  [webidl.brand] = webidl.brand;
  [abortReason] = undefined;
  [abortAlgos] = null;
  [timerId] = null;
  [sourceSignals] = null;
  [dependentSignals] = null;
  [activeDependents] = null;

  static any(signals) {
    const prefix = "Failed to execute 'AbortSignal.any'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    signals = webidl.converters["sequence<AbortSignal>"](
      signals,
      prefix,
      "Argument 1",
    );
    return createDependentAbortSignal(signals);
  }

  static abort(reason = undefined) {
    if (reason !== undefined) {
      reason = webidl.converters.any(reason);
    }
    const signal = new AbortSignal(illegalConstructorKey);
    signal[signalAbort](reason);
    return signal;
  }

  static timeout(millis) {
    const prefix = "Failed to execute 'AbortSignal.timeout'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    millis = webidl.converters["unsigned long long"](
      millis,
      prefix,
      "Argument 1",
      { enforceRange: true },
    );

    const signal = new AbortSignal(illegalConstructorKey);
    signal[timerId] = core.queueSystemTimer(
      undefined,
      false,
      millis,
      () => {
        clearTimeout(signal[timerId]);
        signal[timerId] = null;
        signal[signalAbort](
          new DOMException("Signal timed out.", "TimeoutError"),
        );
      },
    );
    unrefTimer(signal[timerId]);
    return signal;
  }

  [add](algorithm) {
    if (this.aborted) {
      return;
    }
    this[abortAlgos] ??= new SafeSet();
    this[abortAlgos].add(algorithm);
    refSignal(this);
  }

  [remove](algorithm) {
    if (this[abortAlgos]?.delete(algorithm)) {
      tryUnrefSignal(this);
    }
  }

  [signalAbort](
    reason = new DOMException("The signal has been aborted", "AbortError"),
  ) {
    if (this.aborted) {
      return;
    }
    this[abortReason] = reason;

    let dependentSignalsToAbort = null;
    if (this[dependentSignals]) {
      dependentSignalsToAbort = new SafeSet();
      this[dependentSignals].each((dependentSignal) => {
        if (dependentSignal[abortReason] === undefined) {
          dependentSignal[sourceSignals].each((sourceSignal) => {
            sourceSignal[dependentSignals].delete(dependentSignal);
            if (sourceSignal[activeDependents]?.delete(dependentSignal)) {
              tryUnrefSignal(sourceSignal);
            }
          });
          dependentSignal[sourceSignals] = null;
          dependentSignal[abortReason] = reason;
          dependentSignalsToAbort.add(dependentSignal);
        }
      });
      this[dependentSignals] = null;
      this[activeDependents] = null;
    }

    this[runAbortSteps]();

    if (dependentSignalsToAbort) {
      // deno-lint-ignore prefer-primordials
      for (const dependentSignal of dependentSignalsToAbort) {
        dependentSignal[runAbortSteps]();
      }
    }
  }

  [runAbortSteps]() {
    if (this[abortAlgos]) {
      // deno-lint-ignore prefer-primordials
      for (const algorithm of this[abortAlgos]) {
        algorithm();
      }
      this[abortAlgos] = null;
    }

    if (listenerCount(this, "abort") > 0) {
      const event = new Event("abort");
      setIsTrusted(event, true);
      super.dispatchEvent(event);
    }
  }

  constructor(key = null) {
    if (key !== illegalConstructorKey) {
      throw new TypeError("Illegal constructor");
    }
    super();
  }

  get aborted() {
    webidl.assertBranded(this, AbortSignalPrototype);
    return this[abortReason] !== undefined;
  }

  get reason() {
    webidl.assertBranded(this, AbortSignalPrototype);
    return this[abortReason];
  }

  throwIfAborted() {
    webidl.assertBranded(this, AbortSignalPrototype);
    if (this[abortReason] !== undefined) {
      throw this[abortReason];
    }
  }

  addEventListener() {
    FunctionPrototypeApply(super.addEventListener, this, arguments);
    if (listenerCount(this, "abort") > 0) {
      refSignal(this);
    }
  }

  removeEventListener() {
    FunctionPrototypeApply(super.removeEventListener, this, arguments);
    tryUnrefSignal(this);
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(AbortSignalPrototype, this),
        keys: [
          "aborted",
          "reason",
          "onabort",
        ],
      }),
      inspectOptions,
    );
  }
}
defineEventHandler(AbortSignal.prototype, "abort");

webidl.configureInterface(AbortSignal);
const AbortSignalPrototype = AbortSignal.prototype;

class AbortController {
  [signal] = new AbortSignal(illegalConstructorKey);

  constructor() {
    this[webidl.brand] = webidl.brand;
  }

  get signal() {
    webidl.assertBranded(this, AbortControllerPrototype);
    return this[signal];
  }

  abort(reason) {
    webidl.assertBranded(this, AbortControllerPrototype);
    this[signal][signalAbort](reason);
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(AbortControllerPrototype, this),
        keys: [
          "signal",
        ],
      }),
      inspectOptions,
    );
  }
}

webidl.configureInterface(AbortController);
const AbortControllerPrototype = AbortController.prototype;

webidl.converters.AbortSignal = webidl.createInterfaceConverter(
  "AbortSignal",
  AbortSignal.prototype,
);
webidl.converters["sequence<AbortSignal>"] = webidl.createSequenceConverter(
  webidl.converters.AbortSignal,
);

function newSignal() {
  return new AbortSignal(illegalConstructorKey);
}

function createDependentAbortSignal(signals) {
  const resultSignal = new AbortSignal(illegalConstructorKey);
  for (let i = 0; i < signals.length; ++i) {
    const signal = signals[i];
    if (signal[abortReason] !== undefined) {
      resultSignal[abortReason] = signal[abortReason];
      return resultSignal;
    }
  }

  resultSignal[sourceSignals] = new WeakRefSet();
  for (let i = 0; i < signals.length; ++i) {
    const signal = signals[i];
    if (!signal[sourceSignals]) {
      signal[dependentSignals] ??= new WeakRefSet();
      resultSignal[sourceSignals].add(signal);
      signal[dependentSignals].add(resultSignal);
    } else {
      signal[sourceSignals].each((sourceSignal) => {
        resultSignal[sourceSignals].add(sourceSignal);
        sourceSignal[dependentSignals].add(resultSignal);
      });
    }
  }

  return resultSignal;
}

export {
  AbortController,
  AbortSignal,
  AbortSignalPrototype,
  add,
  createDependentAbortSignal,
  newSignal,
  remove,
  signalAbort,
  timerId,
};
