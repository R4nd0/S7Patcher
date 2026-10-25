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
for (const [scenario, reason] of [
  ['architecture', 'architecture-mismatch'], ['missing', 'module-not-ready'],
  ['lookup', 'module-lookup-failed'], ['path', 'process-path-mismatch'],
  ['read', 'target-memory-unreadable'], ['bytes', 'prologue-mismatch'],
  ['allocation', 'replacement-allocation-failed'],
  ['interceptor', 'interceptor-install-failed'], ['success', null],
  ['late-success', null], ['late-bytes', 'prologue-mismatch'],
  ['late-path', 'process-path-mismatch'], ['late-read', 'target-memory-unreadable'],
  ['delayed', 'module-not-ready'],
]) {
  const events = [];
  const pending = [];
  const mode = scenario.startsWith('late-') ? scenario.slice(5) : scenario;
  let attaches = 0, lookups = 0, reads = 0, allocations = 0, time = 0;
  const secretError = () => { throw new Error('test-secret: http://private/?ticket=secret'); };
  const address = {readByteArray: () => {
    reads += 1;
    if (mode === 'read') secretError();
    return Uint8Array.from(mode === 'bytes' ? Array(16).fill(0) : expected).buffer;
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
        return {path: mode === 'path' ? 'test-secret-path' : target,
                base: {add: () => address}};
      },
    },
    Memory: {
      allocUtf8String: () => {
        allocations += 1;
        if (scenario === 'allocation') secretError();
        return {};
      },
      alloc: () => ({writePointer() {}}),
    },
    Interceptor: {attach() {
      attaches += 1;
      if (scenario === 'interceptor') secretError();
    }},
    send: event => events.push(event),
  };
  vm.runInNewContext(source, context);
  while (pending.length) {
    assert.equal(pending.length, 1, 'only one module wait is queued');
    assert.equal(events.length, 0, 'no success before the module is present');
    assert.equal(reads + allocations + attaches, 0, 'no memory/hook actions while absent');
    assert(lookups < 40, 'bounded module retry');
    const next = pending.shift();
    time = next.due + (scenario === 'delayed' ? 2000 : 0);
    next.callback();
  }
  assert.equal(events.length, 1, scenario);
  assert.equal(events[0].event, reason ? 'hook-validation-failed' : 'hook-ready', scenario);
  if (reason) assert.equal(events[0].code, reason, scenario);
  assert.equal(attaches, ['success', 'interceptor'].includes(mode) ? 1 : 0, scenario);
  assert(!JSON.stringify(events).includes('test-secret'), scenario);
  if (scenario === 'missing') {
    assert.equal(lookups, 40);
    assert.equal(time, 1950);
  }
  if (scenario.startsWith('late-')) assert.equal(lookups, 4);
  if (scenario === 'delayed') assert.equal(lookups, 1, 'deadline checked before another lookup');
  count += 1;
}
console.log(`${count} mocked hook setup/timer scenarios passed; no process attached.`);
