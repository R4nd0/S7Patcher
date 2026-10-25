// Research only: replace one sandbox-selection argument in the named test process.
// __TARGET_PATH_JSON__ is filled by the Python watcher after file verification.
const expectedPath = __TARGET_PATH_JSON__;
const normalize = s => s.replace(/\//g, '\\').toLowerCase();
// Keep BOTH allocation objects strongly reachable for the entire script.
// A native pointer stored inside the wrapper does not keep its text alive in JS.
const replacementStorage = {text: null, wrapper: null};
const moduleDeadline = Date.now() + 2000;
let moduleAttempts = 0;
function installHook() {
let stage = 'hook-setup-failed';
const reject = code => send({event: 'hook-validation-failed', code});
try {
if (Process.arch !== 'ia32') { reject('architecture-mismatch'); return; }
// Only a null module lookup is retryable; all actual guards stay exact.
if (moduleAttempts > 0 && Date.now() >= moduleDeadline) {
  reject('module-not-ready');
  return;
}
stage = 'module-lookup-failed';
moduleAttempts += 1;
const moduleInfo = Process.findModuleByName('Settlers7R.exe');
if (moduleInfo === null) {
  if (moduleAttempts >= 40 || Date.now() >= moduleDeadline) {
    reject('module-not-ready');
    return;
  }
  stage = 'hook-setup-failed';
  setTimeout(installHook, 50);
  return;
}
// A module snapshot can disagree during startup. Accept its base only when
// Windows identifies it as the main executable AND returns the exact authorized
// path for that same base. No basename, suffix, short-path or prefix exceptions.
stage = 'native-module-api-unavailable';
const kernel32 = Process.getModuleByName('kernel32.dll');
const getMainModule = new NativeFunction(kernel32.getExportByName('GetModuleHandleW'),
  'pointer', ['pointer'], 'stdcall');
const getModulePath = new NativeFunction(kernel32.getExportByName('GetModuleFileNameW'),
  'uint32', ['pointer', 'pointer', 'uint32'], 'stdcall');
stage = 'native-main-module-query-failed';
const mainModule = getMainModule(ptr(0));
if (mainModule.isNull() || !mainModule.equals(moduleInfo.base)) {
  reject('main-module-mismatch');
  return;
}
stage = 'process-path-validation-failed';
const pathCapacity = 32768;
const pathBuffer = Memory.alloc(pathCapacity * 2);
const pathLength = getModulePath(moduleInfo.base, pathBuffer, pathCapacity);
if (pathLength === 0 || pathLength >= pathCapacity) {
  reject('module-path-unavailable');
  return;
}
const authoritativePath = pathBuffer.readUtf16String(pathLength);
if (normalize(authoritativePath) !== normalize(expectedPath)) { reject('process-path-mismatch'); return; }
const address = moduleInfo.base.add(0xA8A2A0);
const expected = [0x55,0x8b,0xec,0x6a,0xff,0x68,0x32,0xec,0x00,0x01,0x64,0xa1,0x00,0x00,0x00,0x00];
stage = 'target-memory-unreadable';
const actual = new Uint8Array(address.readByteArray(expected.length));
if (expected.some((b, i) => actual[i] !== b)) { reject('prologue-mismatch'); return; }
stage = 'replacement-allocation-failed';
replacementStorage.text = Memory.allocUtf8String('localhost');
replacementStorage.wrapper = Memory.alloc(Process.pointerSize);
replacementStorage.wrapper.writePointer(replacementStorage.text);
Object.freeze(replacementStorage);
let redirects = 0;
stage = 'interceptor-install-failed';
Interceptor.attach(address, {
  onEnter(args) {
    this.redirectId = 0;
    // String is a const char*-wrapper; the helper at E59EA0 uses strlen(*this).
    // Read only the known, nonsecret sandbox identifier. No tokens or URLs.
    let name = '';
    try {
      const text = args[4].readPointer();
      let terminated = false;
      for (let i = 0; i < 15; i++) {
        const byte = text.add(i).readU8();
        if (byte === 0) { terminated = true; break; }
        if (byte > 0x7f) throw new Error('non-ascii-sandbox');
        name += String.fromCharCode(byte);
      }
      if (!terminated) throw new Error('unterminated-sandbox');
    } catch (_) {
      send({event: 'sandbox-read-skipped'});
      return;
    }
    if (name !== 'TSHE_PC_LNCH_A' && (!name || name.toLowerCase() !== 'localhost')) {
      send({event: 'unexpected-sandbox-skipped'});
      return;
    }
    // Pin prevents script unload during argument use; replacementStorage
    // independently retains both allocation objects against garbage collection.
    Script.pin();
    redirects += 1;
    this.redirectId = redirects;
    args[4] = replacementStorage.wrapper;
    send({event: 'sandbox-redirected', count: redirects});
  },
  onLeave() {
    if (this.redirectId === 0) return;
    try {
      send({event: 'sandbox-call-finished', count: this.redirectId});
    } finally {
      Script.unpin();
    }
  }
});
send({event: 'hook-ready', arch: Process.arch});
} catch (_) {
  // Only a fixed stage code crosses the boundary. Never exception text,
  // stack, module path, memory contents, request URLs, or account values.
  reject(stage);
}
}
installHook();
