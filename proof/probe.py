"""Fixed synthetic isolation probe. No EJS code, credentials or task manifests."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys


def denied_write(path):
    try:
        with open(path, 'w') as stream:
            stream.write('SYNTHETIC_ONLY')
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}
    return False


def network_denied(ip, port, family):
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        try:
            client.connect((ip, port))
        except OSError:
            return True
    return False


def run_probe():
    # Only the control-side fixture may be addressed, never a caller URL.
    fixture = ipaddress.ip_address(os.environ['PROBE_FIXTURE_IPV4'])
    if fixture.version != 4 or not fixture.is_private or fixture.is_loopback:
        raise ValueError('invalid synthetic fixture address')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    cpu = Path('/sys/fs/cgroup/cpu.max').read_text().split()
    checks = {
        'non_root': os.getuid() == 65532 and os.getgid() == 65532,
        'no_new_privileges': status['NoNewPrivs'].strip() == '1',
        'capabilities_dropped': int(status['CapEff'].strip(), 16) == 0,
        'seccomp_filter': status['Seccomp'].strip() == '2',
        'memory_limit': Path('/sys/fs/cgroup/memory.max').read_text().strip() == '134217728',
        'pids_limit': Path('/sys/fs/cgroup/pids.max').read_text().strip() == '32',
        'cpu_limit': cpu[0] != 'max' and int(cpu[0]) / int(cpu[1]) == 0.5,
        'reviewed_fixture_readable': Path('/reviewed/fixture.txt').read_text() == 'SYNTHETIC_ONLY\n',
        'source_write_denied': denied_write('/reviewed/fixture.txt'),
        'root_write_denied': denied_write('/forbidden-proof-write'),
        'socket_absent': not Path('/var/run/docker.sock').exists() and not Path('/run/docker.sock').exists(),
        'outside_fixture_absent': not Path('/host-sentinel').exists(),
        'fixture_network_denied': network_denied(str(fixture), 18080, socket.AF_INET),
        'host_gateway_denied': network_denied(os.environ['PROBE_HOST_GATEWAY'], 18080, socket.AF_INET),
        'ipv6_egress_denied': network_denied('2001:db8::1', 18080, socket.AF_INET6),
    }
    # DNS is structural: no non-loopback interface/route. Do not send DNS to a
    # public resolver just to demonstrate a firewall. Runtime net=none is also
    # verified independently on the host.
    interfaces = socket.if_nameindex()
    checks['loopback_only'] = {name for _, name in interfaces} == {'lo'}
    checks['no_credential_env'] = not any(
        word in name.upper() for name in os.environ for word in ('TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL')
    )
    scratch = Path('/tmp/synthetic-proof')
    scratch.write_text('SYNTHETIC_ONLY')
    checks['scratch_only_writable'] = scratch.read_text() == 'SYNTHETIC_ONLY'
    scratch.unlink()
    return checks


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit(2)
    try:
        checks = run_probe()
        print(json.dumps({'schema': 'EJS-ISOLATION-PROBE-1', 'checks': checks}, sort_keys=True))
        raise SystemExit(0 if all(checks.values()) else 1)
    except Exception:
        print('{"schema":"EJS-ISOLATION-PROBE-1","probe_failed":true}')
        raise SystemExit(1)
