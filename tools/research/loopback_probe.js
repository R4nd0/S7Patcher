// Research only: replace one sandbox-selection argument in the named test process.
// __TARGET_PATH_JSON__ is filled by the Python watcher after file verification.
const expectedPath = __TARGET_PATH_JSON__;
const normalize = s => s.replace(/\//g, '\\').toLowerCase();
// Keep BOTH allocation objects strongly reachable for the entire script.
// A native pointer stored inside the wrapper does not keep its text alive in JS.
const replacementStorage = {text: null, wrapper: null};
const moduleDeadline = Date.now() + 2000;
let moduleAttempts = 0;

function localDriveRoot(value) {
  let path = value.replace(/\//g, '\\');
  if (path.startsWith('\\\\?\\')) path = path.slice(4);
  // Exclude UNC/device names, relative paths, NUL/control characters and ADS.
  if (!/^[a-z]:\\/i.test(path) || /[\x00-\x1f]/.test(path) || path.slice(2).includes(':')) return null;
  return path.slice(0, 3);
}

function sameFileIdentity(kernel32, actualPath, authorizedPath) {
  const roots = [localDriveRoot(actualPath), localDriveRoot(authorizedPath)];
  if (roots.some(root => root === null)) return 'file-identity-path-unsupported';
  const handles = [];
  let closeHandle;
  let stage = 'file-identity-api-unavailable';
  try {
    const getDriveType = new NativeFunction(kernel32.getExportByName('GetDriveTypeW'),
      'uint32', ['pointer'], 'stdcall');
    const openFile = new NativeFunction(kernel32.getExportByName('CreateFileW'),
      'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer'], 'stdcall');
    const getFileInfo = new NativeFunction(kernel32.getExportByName('GetFileInformationByHandleEx'),
      'int', ['pointer', 'int', 'pointer', 'uint32'], 'stdcall');
    closeHandle = new NativeFunction(kernel32.getExportByName('CloseHandle'),
      'int', ['pointer'], 'stdcall');
    stage = 'file-identity-drive-query-failed';
    for (const root of roots) {
      const driveType = getDriveType(Memory.allocUtf16String(root));
      if (![2, 3, 5, 6].includes(driveType)) return 'file-identity-path-unsupported';
    }
    stage = 'file-identity-open-failed';
    for (const path of [actualPath, authorizedPath]) {
      // OPEN_EXISTING, metadata access only, share read/write/delete; no writes.
      const handle = openFile(Memory.allocUtf16String(path), 0, 7, ptr(0), 3, 0x80, ptr(0));
      if (handle.isNull() || handle.equals(ptr(-1))) return stage;
      handles.push(handle);
    }
    stage = 'file-identity-query-failed';
    const identities = [];
    for (const handle of handles) {
      const info = Memory.alloc(24); // ULONGLONG volume + FILE_ID_128.
      if (!getFileInfo(handle, 18, info, 24)) return stage; // FileIdInfo.
      identities.push(new Uint8Array(info.readByteArray(24)));
    }
    if (identities[0].some((byte, i) => byte !== identities[1][i])) return 'file-identity-mismatch';
    return null;
  } catch (_) {
    return stage;
  } finally {
    let closeFailed = false;
    for (const handle of handles) {
      try { if (!closeHandle(handle)) closeFailed = true; }
      catch (_) { closeFailed = true; }
    }
    // Both closes are attempted even if the first fails. Never install a hook
    // after an unconfirmed cleanup, regardless of the identity-query result.
    if (closeFailed) return 'file-identity-close-failed';
  }
}

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
// Windows identifies it as the main executable and its path is exact or Windows
// proves that both names refer to the same local file. No basename/suffix tests.
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
let pathValidation = 'native-exact';
if (normalize(authoritativePath) !== normalize(expectedPath)) {
  const identityFailure = sameFileIdentity(kernel32, authoritativePath, expectedPath);
  if (identityFailure !== null) { reject(identityFailure); return; }
  pathValidation = 'native-file-identity';
}
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
send({event: 'hook-ready', arch: Process.arch, path_validation: pathValidation});
} catch (_) {
  // Only a fixed stage code crosses the boundary. Never exception text,
  // stack, module path, memory contents, request URLs, or account values.
  reject(stage);
}
}
installHook();
