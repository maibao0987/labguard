"""Container-local assertions. No public or LAN probing."""

import socket
from pathlib import Path

import httpx

for name in ["vulnerable-web", "fixed-web"]:
    assert httpx.get(f"http://{name}:5000/health", timeout=3, trust_env=False).status_code == 200
routes = Path("/proc/net/route").read_text().splitlines()[1:]
assert not any(line.split()[1] == "00000000" for line in routes), "Unexpected default IPv4 route"
if Path("/proc/net/ipv6_route").exists():
    for line in Path("/proc/net/ipv6_route").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00":
            # Ignore kernel reject/unreachable route entries; reject usable defaults.
            flags = int(fields[8], 16)
            assert not (flags & 1 and not flags & 0x200), "Unexpected usable IPv6 default route"
for name in ["vulnerable-db", "fixed-db"]:
    try:
        socket.getaddrinfo(name, 5432)
    except socket.gaierror:
        pass
    else:
        raise AssertionError("Worker unexpectedly resolves private task DB")
print("PASS: fixed service reachability, no default route, task DB DNS separation")
print("Not proved: host gateway reachability, kernel isolation, Docker Desktop firewall boundary")
