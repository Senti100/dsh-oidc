#!/usr/bin/env python3
"""Synthetic, disposable install smoke for the public web-oidc operator path.

Uses the lock-pinned DSH fixture and source checkout. No live provider, DSH home,
proxy, or credentials are read. Never print the DSH startup stream: it might
contain a temporary bearer URL if a regression re-enables URL printing.
"""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "tests/fixtures/full-profile/node_modules/.bin/dsh"
PEERS = {
    "@deepseek-ai/cordis": "4.0.2",
    "@deepseek-ai/dsh-client-connection": "0.1.5-rc.1",
    "@deepseek-ai/dsh-credentials": "0.1.5-rc.1",
    "@deepseek-ai/dsh-host-webserver": "0.1.5-rc.1",
}


def run(args: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed (exit {result.returncode}); output withheld")
    return result.stdout.strip()


def check_route(port: int) -> bool:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        conn.request(
            "GET", "/auth/check",
            headers={"Host": "dsh.example", "X-Dsh-Oidc-Client-Ip": "127.0.0.1"},
        )
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status == 401
    except (OSError, http.client.HTTPException):
        return False


def main() -> None:
    fixture = json.loads((REPO / "tests/fixtures/full-profile/package.json").read_text())
    overrides = fixture["pnpm"]["overrides"]
    assert len(overrides) == 236
    assert CLI.is_file(), "install the locked full-profile fixture before this smoke"
    with tempfile.TemporaryDirectory(prefix="dsh-oidc-public-install-") as scratch:
        root = Path(scratch)
        home = root / "home"
        env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "LANG", "TMPDIR", "CI", "COREPACK_HOME") if k in os.environ}
        env.update(DSH_HOME=str(home), DSH_TELEMETRY_DISABLED="1")
        run([str(CLI), "--profile", "web-oidc", "--from-default-profile", "web", "--dump-config"], root, env)
        profile = home / "profiles/web-oidc"
        manifest = profile / "package.json"
        package = json.loads(manifest.read_text())
        assert package["name"] == "dsh-profile-web-oidc"
        assert not package.get("dependencies") and not package.get("pnpm")
        package["pnpm"] = {"overrides": overrides}
        manifest.write_text(json.dumps(package, indent=2) + "\n")
        manifest.chmod(0o600)
        tarball = run(["npm", "pack", "--silent", "--pack-destination", scratch], REPO, env).splitlines()[-1]
        run([str(CLI), "plugin", "--profile", "web-oidc", "add", "--save-exact", f"file:{root / tarball}"], root, env)
        run([str(CLI), "plugin", "--profile", "web-oidc", "add", "--save-exact", *(f"{name}@{version}" for name, version in PEERS.items())], root, env)
        patch = profile / "cordis.patch.yml"
        uncommented = [line.strip() for line in patch.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        assert uncommented == ["[]"], "refusing to replace a customized profile patch"
        patch.write_bytes((REPO / "examples/cordis.patch.yml").read_bytes())
        patch.chmod(0o600)
        synthetic_secret = "stub"
        env.update(
            DSH_OIDC_ISSUER="https://identity.example/application/o/dsh/",
            DSH_OIDC_CLIENT_ID="synthetic-id",
            DSH_OIDC_CLIENT_SECRET_REF="DSH_OIDC_CLIENT_SECRET",
            DSH_OIDC_PUBLIC_ORIGIN="https://dsh.example",
            DSH_OIDC_ALLOWED_SUBJECTS='[{"issuer":"https://identity.example/application/o/dsh/","subject":"synthetic-sub"}]',
        )
        env["DSH_OIDC_CLIENT_SECRET"] = synthetic_secret
        dump = run([str(CLI), "--profile", "web-oidc", "--dump-config"], root, env)
        assert "senti100-oidc" in dump and "DSH_OIDC_CLIENT_SECRET_REF" in dump
        assert synthetic_secret not in dump
        installed = json.loads(manifest.read_text())["dependencies"]
        assert installed["@senti100/dsh-oidc"].startswith("file:")
        assert all(installed[name] == version for name, version in PEERS.items())
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        child = subprocess.Popen(
            [str(CLI), "--profile", "web-oidc", "--no-open", "--host", "127.0.0.1", "--port", str(port), "--trusted-host", "dsh.example"],
            cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        admitted = False
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and child.poll() is None:
                if check_route(port):
                    admitted = True
                    break
                time.sleep(0.1)
        finally:
            child.terminate()
            try:
                output, _ = child.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                child.kill()
                output, _ = child.communicate(timeout=5)
        assert admitted, "OIDC auth-check route did not become ready (startup output withheld)"
        assert b"/?token=" not in output, "native bootstrap bearer URL printed despite the public patch"
        assert child.poll() is not None
        assert not check_route(port), "disposable DSH listener survived termination"
    print("public web-oidc install PASS: 236 overrides, exact RC1 peers, auth-check 401, no printed bearer URL, clean teardown")


if __name__ == "__main__":
    main()
