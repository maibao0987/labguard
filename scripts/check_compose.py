"""Static contract, never connects to network."""

from pathlib import Path

import yaml

root = Path(__file__).resolve().parent.parent
data = yaml.safe_load((root / "compose.yaml").read_text("utf-8"))
assert data["name"] == "labguard"
for key, svc in data["services"].items():
    assert not svc.get("privileged") and "network_mode" not in svc
    for port in svc.get("ports", []):
        assert port.startswith("127.0.0.1:")
    for volume in svc.get("volumes", []):
        assert volume.split(":")[0] in data["volumes"]
    if key.endswith("-db"):
        assert not svc.get("ports")
    else:
        assert svc["user"] == "10001:10001" and svc["read_only"]
        for mount in svc.get("tmpfs", []):
            # YAML flow lists split unquoted commas into additional mounts.
            path, separator, options = mount.partition(":")
            assert path.startswith("/"), f"Invalid tmpfs mount path: {path}"
            assert separator and {"noexec", "nosuid"} <= set(options.split(","))
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]
assert not data["networks"]["ingress_net"]["internal"]
assert all(n["internal"] for key, n in data["networks"].items() if key != "ingress_net")
for key, svc in data["services"].items():
    if key != "gateway":
        assert "ingress_net" not in svc["networks"] and not svc.get("ports")
assert set(data["services"]["gateway"]["networks"]) == {"ingress_net", "management_net", "lab_net"}
assert data["services"]["gateway"]["sysctls"]["net.ipv4.ip_forward"] == "0"
assert set(data["services"]["manager"]["networks"]) == {"management_net"}
assert "management_net" not in data["services"]["vulnerable-web"]["networks"]
print("PASS: static Compose security contract (not runtime proof)")
