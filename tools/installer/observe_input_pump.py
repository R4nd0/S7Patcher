"""Read-only counters for the exact, fingerprinted local test game and adapter.

The three adapter RVAs were derived from a private relink map, with .text/.data
bytes and section positions verified against this exact DLL. No game calls,
injection, writes, packet contents, identities, tickets or descriptors.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
from pathlib import Path
import json
import struct
import time

EXE = '4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f'
ADAPTER = 'a59def58f827508d06c95e2787762681f19da4f74390cf205b19f500eaa60b1e'


class Module(c.Structure):
    _fields_ = [('size', w.DWORD), ('module_id', w.DWORD), ('pid', w.DWORD),
        ('global_count', w.DWORD), ('process_count', w.DWORD), ('base', c.c_void_p),
        ('image_size', w.DWORD), ('handle', w.HMODULE), ('name', w.WCHAR * 256), ('path', w.WCHAR * 260)]


class Process(c.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD),
        ('heap', c.c_size_t), ('module_id', w.DWORD), ('threads', w.DWORD),
        ('parent', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD), ('name', w.WCHAR * 260)]


def observe(root):
    root = Path(root).resolve(strict=True)
    expected = root / 'Base/Bin/Settlers7R.exe'
    adapter = expected.with_name('uplay_r1_loader.dll')
    for path, checksum in ((expected, EXE), (adapter, ADAPTER)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
            raise ValueError('Diese Diagnose unterstuetzt nur den bekannten aktuellen Test-Dateistand.')
    k = c.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    k.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]; k.CreateToolhelp32Snapshot.restype = w.HANDLE
    k.Module32FirstW.argtypes = [w.HANDLE, c.POINTER(Module)]; k.Module32NextW.argtypes = [w.HANDLE, c.POINTER(Module)]
    k.Process32FirstW.argtypes = [w.HANDLE, c.POINTER(Process)]; k.Process32NextW.argtypes = [w.HANDLE, c.POINTER(Process)]
    invalid = c.c_void_p(-1).value
    def image_path(pid):
        handle = k.OpenProcess(0x1000, False, pid)
        if not handle: return None
        try:
            value = c.create_unicode_buffer(32768); size = w.DWORD(len(value))
            return Path(value.value) if k.QueryFullProcessImageNameW(handle, 0, value, c.byref(size)) else None
        finally: k.CloseHandle(handle)
    snapshot = k.CreateToolhelp32Snapshot(2, 0)
    if snapshot == invalid: raise RuntimeError('Prozessliste nicht verfuegbar.')
    selected = []
    try:
        item = Process(); item.size = c.sizeof(item)
        valid = k.Process32FirstW(snapshot, c.byref(item))
        while valid:
            if item.name.lower() == 'settlers7r.exe' and image_path(item.pid) == expected:
                if image_path(item.parent) != root / 'Runtime/python/python.exe':
                    raise RuntimeError('Bitte die Testkopie ueber ihren normalen LAN-Starter verwenden.')
                selected.append(item.pid)
            valid = k.Process32NextW(snapshot, c.byref(item))
    finally: k.CloseHandle(snapshot)
    if len(selected) != 1: raise RuntimeError('Genau ein laufendes S7 aus diesem Testordner erforderlich.')
    handle = k.OpenProcess(0x1010, False, selected[0])
    if not handle: raise RuntimeError('Lesender Zugriff auf dieses Testspiel nicht verfuegbar.')
    try:
        if image_path(selected[0]) != expected: raise RuntimeError('Testprozess hat sich geaendert.')
        snapshot = k.CreateToolhelp32Snapshot(0x18, selected[0])
        if snapshot == invalid: raise RuntimeError('Modulliste nicht verfuegbar.')
        base = adapter_base = None
        try:
            module = Module(); module.size = c.sizeof(module)
            valid = k.Module32FirstW(snapshot, c.byref(module))
            while valid:
                if Path(module.path) == expected:
                    if module.image_size != 0x10e7000: raise RuntimeError('Falsche Spiel-Imagegroesse.')
                    base = module.base
                if Path(module.path) == adapter:
                    if module.image_size != 0x44000: raise RuntimeError('Falsche Adapter-Imagegroesse.')
                    adapter_base = module.base
                valid = k.Module32NextW(snapshot, c.byref(module))
        finally: k.CloseHandle(snapshot)
        if not base or not adapter_base: raise RuntimeError('Bekanntes Spielmodul fehlt.')
        def read(address, size):
            if not 0x10000 <= address <= 0xffffffff - size: raise RuntimeError('Ungueltiger x86-Zustandszeiger.')
            value = c.create_string_buffer(size); got = c.c_size_t()
            if not k.ReadProcessMemory(handle, address, value, size, c.byref(got)) or got.value != size:
                raise RuntimeError('Begrenzter Testzustand nicht mehr lesbar.')
            return value.raw
        def u32(address): return struct.unpack('<I', read(address, 4))[0]
        def at(va): return base + va - 0x400000
        def typed(address, table):
            if u32(address) != at(table): raise RuntimeError('Native Typpruefung fehlgeschlagen.')
            return address
        def sample():
            network = u32(at(0x1379e14))
            owner = typed(u32(network + 0xa18), 0x10919bc)
            typed(owner + 0x50, 0x109c9d8)
            master = typed(network + 0x5c, 0x1091e3c)
            core = typed(u32(network + 0x2c), 0x10940a0)
            if u32(master + 0x4c0) != core: raise RuntimeError('Kernzuordnung hat sich geaendert.')
            implementation = typed(u32(core + 0x20), 0x1099548)
            scheduler = typed(u32(implementation + 4), 0x109959c)
            flags = {'master_started':read(master + 0x4c4,1)[0], 'core_enabled':read(master + 0x4c7,1)[0],
                     'external_boundaries':read(network + 0x30,1)[0], 'master_state':u32(master + 0x400),
                     'natural_updates_seen':read(adapter_base + 0x3dfae,1)[0]}
            counters = {'core_dispatches':u32(scheduler + 0x78), 'owner_updates':u32(adapter_base + 0x3e040),
                        'manager_updates':u32(adapter_base + 0x3e044), 'echo_updates':u32(adapter_base + 0x3e048)}
            return scheduler, counters, flags
        previous, counters, flags = sample(); started = time.monotonic()
        print(json.dumps({'event':'input-pump-observation-start', **flags}), flush=True)
        for _ in range(5):
            time.sleep(2)
            current, updated, flags = sample(); now = time.monotonic()
            if current != previous: raise RuntimeError('Scheduler ersetzt; Diagnose beendet.')
            delta = {key:(updated[key] - counters[key]) & 0xffffffff for key in counters}
            print(json.dumps({'event':'input-pump-counter-delta', 'seconds':round(now-started,3), **delta, **flags}), flush=True)
            started = now; counters = updated
    finally: k.CloseHandle(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    try:
        print('S7 Eingabe-Diagnose: nur lesende Zaehler, zehn Sekunden.', flush=True)
        observe(args.bundle)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print('DIAGNOSE BEENDET: ' + str(error), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
