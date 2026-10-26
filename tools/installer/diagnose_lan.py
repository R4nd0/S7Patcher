"""Read-only client preflight for an already installed two-PC test copy.

Place beside Test-LAN-Verbindung.cmd, outside the fingerprinted Launcher folder.
No game launch, runtime configuration write, identity read or firewall change.
"""
import argparse
import base64
import http.client
from pathlib import Path
import socket
import sys


class DiagnosticFailure(Exception):
    def __init__(self, stage, cause):
        self.stage, self.cause = stage, cause


def explain(stage, error):
    code = getattr(error, 'winerror', None) or getattr(error, 'errno', None)
    if code == 10049:
        reason = 'Die eingegebene eigene IPv4-Adresse gehoert nicht zu diesem PC. In Windows unter Netzwerk/Eigenschaften nachsehen.'
    elif isinstance(error, TimeoutError) or code in (10060, 110):
        reason = 'Der Host antwortet nicht rechtzeitig. Hostadresse, TCP-Port 9110 und Netzwerkfreigabe pruefen.'
    elif isinstance(error, ConnectionRefusedError) or code in (10061, 111):
        reason = 'Die Verbindung wurde abgelehnt. Am Ziel muss Test-LAN-Host.cmd laufen und TCP-Port 9110 erreichbar sein.'
    elif code in (10013, 13, 5):
        reason = 'Windows verweigert den Zugriff. Dateiberechtigungen oder Netzwerkregel pruefen.'
    else:
        reason = {
            'Ordner': 'Die Pruefung muss im vorbereiteten Spielordner neben Test-LAN-Verbindung.cmd liegen.',
            'Adressen': 'Zwei verschiedene private IPv4-Adressen eingeben: zuerst diesen PC, dann den Host.',
            'Dateipruefung': 'Die vorbereiteten Dateien sind unvollstaendig oder seit der Installation veraendert.',
            'Eigene Adresse': 'Die eigene IPv4-Adresse konnte auf diesem PC nicht verwendet werden.',
            'Hostverbindung': 'Der Host liefert keine gueltige Konfiguration. Hoststarter und Netzwerk pruefen.',
            'Dateivergleich': 'Host und dieser PC haben unterschiedliche Spiel- oder Patchdateien. Dasselbe Installationspaket verwenden.',
            'Serverkonfiguration': 'Serveradresse, Port oder Schluesselformat passen nicht zum LAN-Test.',
        }.get(stage, 'Die Pruefung wurde abgebrochen.')
    suffix = f' Windows-/Systemcode: {code}.' if isinstance(code, int) else ''
    return f'FEHLER bei {stage}: {reason}{suffix}'


def check(root, local, host, *, compatibility, launcher, local_launcher, emit=print):
    def step(label, action):
        emit('Pruefe: ' + label, flush=True)
        try:
            result = action()
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, http.client.HTTPException) as error:
            raise DiagnosticFailure(label, error) from None
        emit('OK: ' + label, flush=True)
        return result

    step('Adressen', lambda: local_launcher.lan_pair(local, host))
    root = step('Ordner', lambda: compatibility.plain(root))
    def files():
        if (root / 'INSTALLATION-INCOMPLETE.txt').exists():
            raise ValueError('incomplete')
        result = compatibility.verify(root)
        local_launcher.verify_bundle(root)
        return result['content_id']
    content = step('Dateipruefung', files)
    def own_address():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((local, 0))
    step('Eigene Adresse', own_address)
    configuration = step('Hostverbindung', lambda: launcher.remote_configuration(host, local))
    step('Dateivergleich', lambda: launcher.check_content(configuration, content))
    def server_configuration():
        if configuration.get('prudp_urls') != [f'prudp:/address={host};port={launcher.UDP_PORT}']:
            raise ValueError('endpoint')
        public = configuration.get('public_key')
        if not isinstance(public, str) or len(public) != 96:
            raise ValueError('key')
        blob = base64.b64decode(public, validate=True)
        if len(blob) != 72 or blob[:8] != b'ECS1\x20\0\0\0':
            raise ValueError('key')
    step('Serverkonfiguration', server_configuration)
    emit('Pruefung bestanden. Kein Spiel gestartet. Jetzt den normalen LAN-Starter mit denselben Adressen verwenden.', flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', default=str(Path(__file__).resolve().parent))
    parser.add_argument('--local')
    parser.add_argument('--host')
    args = parser.parse_args()
    root = Path(args.bundle).absolute()
    try:
        sys.path.insert(0, str(root / 'Launcher'))
        import compatibility
        import launch_lan
        import launch_local
    except ImportError:
        print(explain('Ordner', ValueError('missing modules')))
        return 2
    try:
        print('S7 LAN-Pruefung: keine Aenderung am Spiel oder an Windows.')
        local = args.local or input('IPv4-Adresse dieses PCs: ').strip()
        host = args.host or input('IPv4-Adresse des Hosts: ').strip()
        return check(root, local, host, compatibility=compatibility, launcher=launch_lan, local_launcher=launch_local)
    except DiagnosticFailure as failure:
        print(explain(failure.stage, failure.cause), flush=True)
        return 2
    except EOFError:
        print('Eingabe abgebrochen. Bitte die Pruefung per Doppelklick starten.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
