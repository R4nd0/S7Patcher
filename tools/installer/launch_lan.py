"""Explicit two-PC catalogue experiment; not a verified playable LAN mode."""
import argparse
import http.client
import json
import msvcrt
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compatibility
import launch_local

HTTP_PORT, UDP_PORT = 9110, 9111
SERVICE_SECONDS = 86400


def check_content(configuration, expected):
    if configuration.get('content_id') != expected:
        raise ValueError('Spiel- oder Patchstand unterscheiden sich. Beide Kopien mit demselben Paket vorbereiten.')


def remote_configuration(address, local):
    # Numeric address only, no DNS discovery, HTTP redirects or system proxy.
    connection = http.client.HTTPConnection(address, HTTP_PORT, timeout=5, source_address=(local, 0))
    try:
        connection.request('GET', '/public/rendezvous/v1/configuration')
        response = connection.getresponse()
        body = response.read(8193)
        if response.status != 200 or len(body) > 8192:
            raise ValueError('Der Host liefert keine passende LAN-Konfiguration.')
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError('Ungueltige LAN-Konfiguration.')
        return value
    finally:
        connection.close()


def run(args):
    local, peer = launch_local.lan_pair(args.local, args.peer)
    if args.role not in ('host', 'client'):
        raise ValueError('Bitte Host oder Mitspieler auswaehlen.')
    root = compatibility.plain(Path(args.bundle))
    if (root / 'INSTALLATION-INCOMPLETE.txt').exists():
        raise ValueError('Die Installation ist noch nicht abgeschlossen.')
    expected = compatibility.verify(root)['content_id']
    launch_local.verify_bundle(root)
    # Fails before launching anything if the configured local address is not on this PC.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((local, 0))
    data = root / 'LocalData'
    launch_local.plain_path(data, root)
    data.mkdir(exist_ok=True)
    lock_path = data / 'session.lock'
    launch_local.plain_path(lock_path, root)
    with lock_path.open('a+b') as lock:
        if lock.tell() == 0:
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError('Diese Testkopie laeuft bereits.') from None
        service = runtime = None
        try:
            run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
            address = local if args.role == 'host' else peer
            if args.role == 'host':
                log = data / (run_id + '-lan-server.jsonl')
                errors = data / (run_id + '-lan-errors.txt')
                with log.open('xb') as output, errors.open('xb') as error:
                    service = subprocess.Popen([str(root / 'Runtime/dotnet/dotnet.exe'), str(root / 'Server/S7Patcher.dll'),
                        '--local-config-server', '--local-catalogue-probe', '--lan-address', local, '--lan-peer', peer,
                        '--content-id', expected, '--http-port', str(HTTP_PORT), '--udp-port', str(UDP_PORT), '--seconds', str(SERVICE_SECONDS)],
                        stdout=output, stderr=error, creationflags=subprocess.CREATE_NO_WINDOW)
                    configuration, port = launch_local.service_ready(service, log, address)
                if port != UDP_PORT:
                    raise ValueError('Unerwarteter LAN-Port.')
            else:
                configuration = remote_configuration(peer, local)
            check_content(configuration, expected)
            runtime = launch_local.write_configuration(data, configuration, UDP_PORT, True, address=address, lan=(local, peer))
            print('LAN-Konfiguration und Dateistand stimmen ueberein.', flush=True)
            if args.check_only:
                print('Startpruefung bestanden. Kein Spiel gestartet.', flush=True)
                return 0
            if service is not None and service.poll() is not None:
                raise RuntimeError('Der LAN-Dienst wurde beendet.')
            print('LAN-Sitzungstest: Beitritt und Spielstart sind noch in Entwicklung.', flush=True)
            game = subprocess.Popen([str(root / 'Base/Bin/Settlers7R.exe')], cwd=root / 'Base/Bin')
            code = game.wait()
            with (data / (run_id + '-game-exit.txt')).open('x', encoding='ascii') as output:
                output.write(str(code) + '\n')
            return 0 if code == 0 else 1
        finally:
            if runtime is not None and runtime.exists():
                launch_local.plain_path(runtime, root)
                runtime.unlink()
            if service is not None and service.poll() is None:
                service.terminate(); service.wait(timeout=10)
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--role', choices=('host', 'client'))
    parser.add_argument('--local')
    parser.add_argument('--peer')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    try:
        print('LAN-Verbindungstest fuer zwei PCs. Noch keine freigegebene Mehrspielerpartie.')
        if args.role is None:
            choice = input('1 = Sitzung anbieten, 2 = Sitzung suchen: ').strip()
            args.role = {'1': 'host', '2': 'client'}.get(choice)
        args.local = args.local or input('IPv4-Adresse dieses PCs: ').strip()
        args.peer = args.peer or input('IPv4-Adresse des anderen PCs: ').strip()
        return run(args)
    except (OSError, ValueError, RuntimeError, EOFError, http.client.HTTPException):
        print('LAN-Start abgebrochen. Adressen, Dateistand, laufenden Host und Firewallfreigabe pruefen.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
