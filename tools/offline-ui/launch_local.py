"""Start/check an explicitly prepared experimental local bundle.

Without --launch-game this only checks the bundle and local service and exits.
No launcher, account cache, system hosts file or firewall setting is accessed.
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import msvcrt
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

EXE_HASH = "4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f"


def plain_path(path, root):
    """Reject links/junctions all the way to the explicit owned bundle root."""
    if not path.is_relative_to(root):
        raise ValueError("Dateipfad liegt ausserhalb der Testversion.")
    cursor = path
    while True:
        if cursor.is_symlink() or cursor.is_junction():
            raise ValueError("Verknuepfungen werden in der Testversion nicht verwendet.")
        if cursor == root:
            break
        cursor = cursor.parent


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_bundle(root):
    manifest_path = root / "local-bundle.json"
    plain_path(manifest_path, root)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_paths = {"Base/Bin/Settlers7R.exe", "Base/Bin/uplay_r1_loader.dll", "Base/BBA/Interface.bba"}
    if manifest.get("format") != "s7-local-experimental-v1" or set(manifest.get("files", {})) != expected_paths:
        raise ValueError("Die Testversion hat kein gueltiges Manifest.")
    if manifest["files"]["Base/Bin/Settlers7R.exe"] != EXE_HASH:
        raise ValueError("Diese Spielversion wird nicht unterstuetzt.")
    for name, expected in manifest["files"].items():
        path = root / name
        plain_path(path, root)
        if not re.fullmatch("[0-9a-f]{64}", expected) or digest(path) != expected:
            raise ValueError("Die Dateien der Testversion haben sich geaendert.")


def local_identity(data):
    path = data / "local-profile-id.txt"
    plain_path(path, data)
    if not path.exists():
        with path.open("x", encoding="ascii") as stream:
            stream.write(str(uuid.uuid4()) + "\n")
    value = path.read_text(encoding="ascii").strip()
    if len(value) != 36 or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError("Die lokale Profilkennung ist ungueltig.")
    return value


def lan_pair(local, peer):
    addresses = []
    for text in (local, peer):
        address = ipaddress.IPv4Address(text)
        if str(address) != text or address.packed[-1] in (0, 255) or not any(
                address in ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            raise ValueError("Bitte zwei genaue private IPv4-Adressen angeben.")
        addresses.append(address)
    if addresses[0] == addresses[1]:
        raise ValueError("Die beiden PCs brauchen unterschiedliche Adressen.")
    return local, peer


def write_configuration(data, configuration, udp_port, connect_probe=False, *, address="127.0.0.1", lan=None):
    if lan is not None:
        lan = lan_pair(*lan)
        if address not in lan or not connect_probe:
            raise ValueError("LAN-Serveradresse passt nicht zu den beiden PCs.")
    elif address != "127.0.0.1":
        raise ValueError("LAN benoetigt die explizite Konfiguration beider PCs.")
    if type(udp_port) is not int or not 1 <= udp_port <= 65535:
        raise ValueError("Ungueltiger Serverport.")
    public = configuration.get("public_key")
    if not isinstance(public, str) or len(public) != 96:
        raise ValueError("Der lokale Dienst liefert keinen gueltigen oeffentlichen Schluessel.")
    blob = base64.b64decode(public, validate=True)
    if len(blob) != 72 or blob[:8] != b"ECS1\x20\0\0\0":
        raise ValueError("Der lokale Dienst verwendet ein unbekanntes Schluesselformat.")
    if configuration.get("prudp_urls") != [f"prudp:/address={address};port={udp_port}"]:
        raise ValueError("Die lokale Serveradresse stimmt nicht ueberein.")
    profile = local_identity(data)
    content = (f"format=s7-local-runtime-v1\naddress={address}\n"
               f"udp_port={udp_port}\npublic_key={public}\nprofile_id={profile}\n"
               f"display_name=LocalPlayer\nticket=local-s7:{profile}\n")
    if connect_probe:
        content += "connect_probe=1\n"
    if lan is not None:
        content += f"lan_local={lan[0]}\nlan_peer={lan[1]}\n"
    destination = data / "s7-local-runtime.ini"
    plain_path(destination, data)
    if destination.exists() and not destination.read_bytes().startswith(b"format=s7-local-runtime-v1\n"):
        raise ValueError("Eine unbekannte Konfigurationsdatei wird nicht ueberschrieben.")
    temporary = data / ("runtime-" + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def service_ready(process, log, address="127.0.0.1"):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Der lokale Dienst konnte nicht starten.")
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") == "configuration-server-ready":
                http_port, udp_port = record.get("http_port"), record.get("udp_port")
                if not all(type(port) is int and 1 <= port <= 65535 for port in (http_port, udp_port)):
                    raise ValueError("Der lokale Dienst hat ungueltige Portangaben geliefert.")
                connection = http.client.HTTPConnection(address, http_port, timeout=3)
                try:
                    connection.request("GET", "/public/rendezvous/v1/configuration")
                    response = connection.getresponse()
                    body = response.read(8193)
                    if response.status != 200 or len(body) > 8192:
                        raise ValueError("Die lokale Konfiguration konnte nicht gelesen werden.")
                    return json.loads(body), udp_port
                finally:
                    connection.close()
        time.sleep(0.1)
    raise TimeoutError("Der lokale Dienst ist nicht rechtzeitig bereit geworden.")


def run(args):
    display_probe = getattr(args, "local_session_display_probe", False)
    if display_probe and not args.local_connect_probe:
        raise ValueError("Der Anzeigetest benoetigt die lokale Anmeldung.")
    root = Path(args.bundle).absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("Der Testordner darf keine Verknuepfung sein.")
    verify_bundle(root)
    data = root / "LocalData"
    plain_path(data, root)
    data.mkdir(exist_ok=True)
    lock_path = data / "session.lock"
    plain_path(lock_path, root)
    with lock_path.open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"0"); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError("Diese lokale Testversion laeuft bereits.") from None
        service = None
        runtime = None
        try:
            run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
            log = data / (run_id + "-server.jsonl")
            errors = data / (run_id + "-server-errors.txt")
            with log.open("xb") as output, errors.open("xb") as error_output:
                service = subprocess.Popen([str(Path(args.dotnet).resolve(strict=True)), str(Path(args.server).resolve(strict=True)),
                    "--local-config-server", "--local-session-display-probe" if display_probe else (
                        "--local-keepalive-probe" if args.local_connect_probe else "--local-login-probe"),
                    "--http-port", "0", "--udp-port", "0", "--seconds", "3600"],
                    stdout=output, stderr=error_output, creationflags=subprocess.CREATE_NO_WINDOW)
                configuration, udp_port = service_ready(service, log)
                runtime = write_configuration(data, configuration, udp_port, args.local_connect_probe)
                if service.poll() is not None:
                    raise RuntimeError("Der lokale Dienst wurde vor dem Spielstart beendet.")
                print("Lokale Testversion und Dienst sind bereit.", flush=True)
                if display_probe:
                    print("Anzeigetest: Lobby erstellen, verlassen, Sitzungsliste ansehen. Dem Testeintrag nicht beitreten.", flush=True)
                if not args.launch_game:
                    print("Startpruefung bestanden. Kein Spiel gestartet.", flush=True)
                    return 0
                print("Starte die getrennte Testversion. Lokaler Server und LAN sind noch unvollstaendig.", flush=True)
                game = subprocess.Popen([str(root / "Base/Bin/Settlers7R.exe")], cwd=root / "Base/Bin")
                code = game.wait()
                with (data / (run_id + "-game-exit.txt")).open("x", encoding="ascii") as stream:
                    stream.write(str(code) + "\n")
                if code:
                    print("Das Spiel wurde mit einem Fehler beendet. Das lokale Startprotokoll wurde gespeichert.", flush=True)
                return 0 if code == 0 else 1
        finally:
            if runtime is not None and runtime.exists():
                plain_path(runtime, root)
                runtime.unlink()
            if service is not None and service.poll() is None:
                service.terminate()  # Only this helper's child, never a global process search.
                service.wait(timeout=10)
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--launch-game", action="store_true")
    parser.add_argument("--local-connect-probe", action="store_true", help="Experimental native local login trigger; off by default")
    parser.add_argument("--local-session-display-probe", action="store_true", help="Show a labelled copy of your last left lobby; no joining")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, TimeoutError, http.client.HTTPException):
        # Never echo unexpected exception text containing runtime configuration.
        print("Startpruefung fehlgeschlagen. Die lokale Testversion wurde nicht gestartet.", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
