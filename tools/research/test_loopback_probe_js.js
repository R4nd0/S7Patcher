// Node built-ins only. Runs the real hook source against mocks, never Frida.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const target = 'C:\\authorized\\Settlers7R.exe';
const source = fs.readFileSync(path.join(__dirname, 'loopback_probe.js'), 'utf8')
  .replaceAll('__TARGET_PATH_JSON__', JSON.stringify(target));
const expected = [0x55,0x8b,0xec,0x6a,0xff,0x68,0x32,0xec,0x00,0x01,0x64,0xa1,0,0,0,0];
let count = 0;
let lifetimeChecks = 0;
for (const [scenario, reason] of [
  ['architecture', 'architecture-mismatch'], ['missing', 'module-not-ready'],
  ['lookup', 'module-lookup-failed'], ['path', 'file-identity-path-unsupported'],
  ['read', 'target-memory-unreadable'], ['bytes', 'prologue-mismatch'],
  ['allocation', 'replacement-allocation-failed'],
  ['interceptor', 'interceptor-install-failed'], ['success', null],
  ['late-success', null], ['late-bytes', 'prologue-mismatch'],
  ['late-path', 'file-identity-path-unsupported'], ['late-read', 'target-memory-unreadable'],
  ['delayed', 'module-not-ready'],
  ['snapshot-different', null], ['path-case-slash', null],
  ['path-short', null], ['path-prefix', null], ['path-dots', null],
  ['native-module-missing', 'native-module-api-unavailable'],
  ['native-export-missing', 'native-module-api-unavailable'],
  ['native-constructor', 'native-module-api-unavailable'],
  ['native-main-throws', 'native-main-module-query-failed'],
  ['native-main-null', 'main-module-mismatch'],
  ['native-main-different', 'main-module-mismatch'],
  ['native-path-zero', 'module-path-unavailable'],
  ['native-path-truncated', 'module-path-unavailable'],
  ['native-path-throws', 'process-path-validation-failed'],
  ['native-path-read', 'process-path-validation-failed'],
  ['native-path-allocation', 'process-path-validation-failed'],
  ['file-id-different', 'file-identity-mismatch'], ['file-volume-different', 'file-identity-mismatch'],
  ['file-api', 'file-identity-api-unavailable'],
  ['file-drive-throws', 'file-identity-drive-query-failed'],
  ['file-drive-remote', 'file-identity-path-unsupported'],
  ['file-drive-unknown', 'file-identity-path-unsupported'],
  ['file-unc', 'file-identity-path-unsupported'], ['file-device', 'file-identity-path-unsupported'],
  ['file-unc-prefix', 'file-identity-path-unsupported'],
  ['file-globalroot', 'file-identity-path-unsupported'],
  ['file-relative', 'file-identity-path-unsupported'], ['file-drive-relative', 'file-identity-path-unsupported'],
  ['file-ads', 'file-identity-path-unsupported'], ['file-nul', 'file-identity-path-unsupported'],
  ['file-open-first-fails', 'file-identity-open-failed'],
  ['file-open-second-fails', 'file-identity-open-failed'],
  ['file-open-second-throws', 'file-identity-open-failed'],
  ['file-query-first-fails', 'file-identity-query-failed'],
  ['file-query-second-fails', 'file-identity-query-failed'],
  ['file-query-second-throws', 'file-identity-query-failed'],
  ['file-query-read-throws', 'file-identity-query-failed'],
  ['file-close-first-fails', 'file-identity-close-failed'],
  ['file-close-first-throws', 'file-identity-close-failed'],
  ['file-close-second-fails', 'file-identity-close-failed'],
]) {
  const events = [];
  const pending = [];
  const mode = scenario.startsWith('late-') ? scenario.slice(5) : scenario;
  let attaches = 0, lookups = 0, reads = 0, allocations = 0, time = 0, nativeCalls = 0;
  let callbacks, pins = 0, writtenTextAddress;
  let fileOpens = 0, fileQueries = 0;
  const openedHandles = [], closedHandles = [];
  const textAllocation = {allocationId: 'replacement-text'};
  const wrapperAllocation = {writePointer(value) {
    // Model a native pointer write without retaining the JS allocation object.
    writtenTextAddress = value.allocationId;
  }};
  const secretError = () => { throw new Error('test-secret: http://private/?ticket=secret'); };
  const address = {readByteArray: () => {
    reads += 1;
    if (mode === 'read') secretError();
    return Uint8Array.from(mode === 'bytes' ? Array(16).fill(0) : expected).buffer;
  }};
  const base = {add(offset) { assert.equal(offset, 0xA8A2A0); return address; }};
  const nullPointer = {isNull: () => true};
  const invalidPointer = {isNull: () => false, equals: other => other === invalidPointer};
  const mainModule = {
    isNull: () => mode === 'native-main-null',
    equals: other => mode !== 'native-main-different' && other === base,
  };
  let authoritativePath = target;
  if (mode === 'path') authoritativePath = 'test-secret-path';
  if (mode === 'path-short') authoritativePath = 'C:\\AUTH~1\\Settlers7R.exe';
  if (mode === 'path-prefix') authoritativePath = '\\\\?\\' + target;
  if (mode === 'path-dots') authoritativePath = 'C:\\authorized\\.\\child\\..\\Settlers7R.exe';
  if (mode === 'path-case-slash') authoritativePath = target.toUpperCase().replaceAll('\\', '/');
  if (mode.startsWith('file-')) authoritativePath = 'C:\\alias\\Settlers7R.exe';
  const unsupportedPaths = {
    'file-unc': '\\\\server\\share\\Settlers7R.exe',
    'file-device': '\\\\.\\C:\\authorized\\Settlers7R.exe',
    'file-unc-prefix': '\\\\?\\UNC\\server\\share\\Settlers7R.exe',
    'file-globalroot': '\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Settlers7R.exe',
    'file-relative': 'authorized\\Settlers7R.exe',
    'file-drive-relative': 'C:authorized\\Settlers7R.exe',
    'file-ads': target + ':stream',
    'file-nul': target + '\0extra',
  };
  if (unsupportedPaths[mode]) authoritativePath = unsupportedPaths[mode];
  const pathBuffer = {readUtf16String(length) {
    if (mode === 'native-path-read') secretError();
    assert.equal(length, authoritativePath.length, 'bounded read excludes NUL');
    return authoritativePath;
  }};
  const context = {
    Date: {now: () => time},
    setTimeout: (callback, delay) => {
      assert.equal(delay, 50);
      pending.push({callback, due: time + delay});
    },
    Process: {
      arch: scenario === 'architecture' ? 'x64' : 'ia32', pointerSize: 4,
      findModuleByName: () => {
        lookups += 1;
        if (scenario === 'lookup') secretError();
        if (scenario === 'missing') return null;
        if (scenario.startsWith('late-') && lookups <= 3) return null;
        if (scenario === 'delayed' && lookups === 1) return null;
        return {path: mode === 'snapshot-different' ? 'test-secret-snapshot-path' : target, base};
      },
      getModuleByName(name) {
        assert.equal(name, 'kernel32.dll');
        if (mode === 'native-module-missing') secretError();
        return {getExportByName(exportName) {
          if (mode === 'native-export-missing' || mode === 'file-api' && exportName === 'CreateFileW') secretError();
          return exportName;
        }};
      },
    },
    ptr(value) { assert([0, -1].includes(value)); return value === 0 ? nullPointer : invalidPointer; },
    NativeFunction: function (name, resultType, argTypes, abi) {
      assert.equal(abi, 'stdcall', 'explicit Windows ia32 ABI');
      if (mode === 'native-constructor') secretError();
      if (name === 'GetModuleHandleW') {
        assert.equal(resultType, 'pointer');
        assert.deepEqual(Array.from(argTypes), ['pointer']);
        return argument => {
          nativeCalls += 1;
          assert.equal(argument, nullPointer, 'NULL selects the main executable');
          if (mode === 'native-main-throws') secretError();
          return mainModule;
        };
      }
      if (name === 'GetDriveTypeW') {
        assert.equal(resultType, 'uint32');
        assert.deepEqual(Array.from(argTypes), ['pointer']);
        return root => {
          assert.equal(root.text.toUpperCase(), 'C:\\');
          if (mode === 'file-drive-throws') secretError();
          return mode === 'file-drive-remote' ? 4 : mode === 'file-drive-unknown' ? 0 : 3;
        };
      }
      if (name === 'CreateFileW') {
        assert.equal(resultType, 'pointer');
        assert.deepEqual(Array.from(argTypes), ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']);
        return (file, access, share, security, disposition, flags, template) => {
          const index = fileOpens++;
          assert.equal(file.text, index === 0 ? authoritativePath : target);
          assert.equal(access, 0); assert.equal(share, 7); assert.equal(disposition, 3);
          assert.equal(security, nullPointer); assert.equal(flags, 0x80); assert.equal(template, nullPointer);
          if (mode === 'file-open-second-throws' && index === 1) secretError();
          if (mode === 'file-open-first-fails' && index === 0 || mode === 'file-open-second-fails' && index === 1)
            return invalidPointer;
          const handle = {index, isNull: () => false, equals: other => other === handle};
          openedHandles.push(index);
          return handle;
        };
      }
      if (name === 'GetFileInformationByHandleEx') {
        assert.equal(resultType, 'int');
        assert.deepEqual(Array.from(argTypes), ['pointer', 'int', 'pointer', 'uint32']);
        return (handle, infoClass, buffer, length) => {
          fileQueries += 1;
          assert.equal(infoClass, 18); assert.equal(length, 24);
          if (mode === 'file-query-second-throws' && handle.index === 1) secretError();
          if (mode === 'file-query-first-fails' && handle.index === 0 || mode === 'file-query-second-fails' && handle.index === 1)
            return 0;
          buffer.value = Uint8Array.from({length: 24}, (_, i) => i + 1);
          if (mode === 'file-id-different' && handle.index === 1) buffer.value[8] ^= 1;
          if (mode === 'file-volume-different' && handle.index === 1) buffer.value[0] ^= 1;
          return 1;
        };
      }
      if (name === 'CloseHandle') {
        assert.equal(resultType, 'int');
        assert.deepEqual(Array.from(argTypes), ['pointer']);
        return handle => {
          assert(!closedHandles.includes(handle.index), 'each owned handle closes once');
          closedHandles.push(handle.index);
          if (mode === 'file-close-first-throws' && handle.index === 0) secretError();
          if (mode === 'file-close-first-fails' && handle.index === 0 || mode === 'file-close-second-fails' && handle.index === 1)
            return 0;
          return 1;
        };
      }
      assert.equal(name, 'GetModuleFileNameW');
      assert.equal(resultType, 'uint32');
      assert.deepEqual(Array.from(argTypes), ['pointer', 'pointer', 'uint32']);
      return (module, buffer, capacity) => {
        nativeCalls += 1;
        assert.equal(module, base, 'query precisely the validated main-module base');
        assert.equal(buffer, pathBuffer);
        assert.equal(capacity, 32768);
        if (mode === 'native-path-throws') secretError();
        if (mode === 'native-path-zero') return 0;
        if (mode === 'native-path-truncated') return capacity;
        return authoritativePath.length;
      };
    },
    Memory: {
      allocUtf16String: text => ({text}),
      allocUtf8String: () => {
        allocations += 1;
        if (scenario === 'allocation') secretError();
        return textAllocation;
      },
      alloc(size) {
        allocations += 1;
        if (size === 65536) {
          if (mode === 'native-path-allocation') secretError();
          return pathBuffer;
        }
        if (size === 24) return {value: null, readByteArray(length) {
          assert.equal(length, 24);
          if (mode === 'file-query-read-throws') secretError();
          return this.value.buffer;
        }};
        assert.equal(size, 4);
        return wrapperAllocation;
      },
    },
    Script: {pin() { pins += 1; }, unpin() { assert(pins > 0); pins -= 1; }},
    Interceptor: {attach(_address, hookCallbacks) {
      attaches += 1;
      if (scenario === 'interceptor') secretError();
      callbacks = hookCallbacks;
    }},
    send: event => events.push(event),
  };
  vm.runInNewContext(source, context);
  while (pending.length) {
    assert.equal(pending.length, 1, 'only one module wait is queued');
    assert.equal(events.length, 0, 'no success before the module is present');
    assert.equal(reads + allocations + attaches + nativeCalls, 0,
      'no memory/native/hook actions while absent');
    assert(lookups < 40, 'bounded module retry');
    const next = pending.shift();
    time = next.due + (scenario === 'delayed' ? 2000 : 0);
    next.callback();
  }
  assert.equal(events.length, 1, scenario);
  assert.equal(events[0].event, reason ? 'hook-validation-failed' : 'hook-ready', scenario);
  if (reason) assert.equal(events[0].code, reason, scenario);
  assert.equal(attaches, reason === null || mode === 'interceptor' ? 1 : 0, scenario);
  assert(!JSON.stringify(events).includes('test-secret'), scenario);
  assert.deepEqual(closedHandles, openedHandles, 'all successfully opened handles receive cleanup');
  if (reason === 'file-identity-path-unsupported' || reason === 'file-identity-api-unavailable')
    assert.equal(fileOpens, 0, 'unsupported paths/APIs never open a file');
  if (scenario === 'missing') {
    assert.equal(lookups, 40);
    assert.equal(time, 1950);
  }
  if (scenario.startsWith('late-')) assert.equal(lookups, 4);
  if (scenario === 'delayed') assert.equal(lookups, 1, 'deadline checked before another lookup');
  if (reason === null) {
    const expectedValidation = ['path-short', 'path-prefix', 'path-dots'].includes(mode)
      ? 'native-file-identity' : 'native-exact';
    assert.equal(events[0].path_validation, expectedValidation);
    assert.equal(fileQueries, expectedValidation === 'native-file-identity' ? 2 : 0,
      'only a native path mismatch queries file identity');
    // installHook has returned: both allocations must still have explicit JS
    // roots. Pinning the script alone cannot provide these allocation roots.
    const retained = vm.runInContext('replacementStorage', context);
    assert.equal(retained.text, textAllocation);
    assert.equal(retained.wrapper, wrapperAllocation);
    assert(Object.isFrozen(retained), 'retention cannot accidentally be cleared');
    assert.equal(writtenTextAddress, textAllocation.allocationId);
    const sandbox = Buffer.from('TSHE_PC_LNCH_A\0', 'ascii');
    const sandboxPointer = {add(offset) { return {readU8() {
      assert(offset < sandbox.length, 'sandbox read stops at NUL');
      return sandbox[offset];
    }}; }};
    const args = [null, null, null, null, {readPointer: () => sandboxPointer}];
    const invocation = {};
    callbacks.onEnter.call(invocation, args);
    assert.equal(args[4], retained.wrapper, 'callback uses the rooted wrapper');
    assert.equal(pins, 1);
    assert.equal(events.at(-1).event, 'sandbox-redirected');
    callbacks.onLeave.call(invocation);
    assert.equal(pins, 0);
    assert.equal(events.at(-1).event, 'sandbox-call-finished');
    assert.equal(retained.text, textAllocation, 'allocation survives constructor return');
    lifetimeChecks += 1;
  }
  count += 1;
}
console.log(`${count} mocked hook setup/timer scenarios and ${lifetimeChecks} allocation-lifetime checks passed; no process attached.`);
