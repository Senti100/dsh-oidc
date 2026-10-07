#!/usr/bin/env python3
"""Synthetic, disposable install smoke for the public web-oidc operator path.

Uses the lock-pinned DSH fixture and source checkout. No live provider, DSH home,
proxy, or credentials are read. Never print the DSH startup stream: it might
contain a temporary bearer URL if a regression re-enables URL printing.
"""

from __future__ import annotations

import ast
import http.client
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "tests/fixtures/full-profile/node_modules/.bin/dsh"
PEERS = {
    "@deepseek-ai/cordis": "4.0.4",
    "@deepseek-ai/dsh-client-connection": "0.2.0-rc.2",
    "@deepseek-ai/dsh-credentials": "0.2.0-rc.2",
    "@deepseek-ai/dsh-host-webserver": "0.2.0-rc.2",
}


def require(condition: bool, message: str) -> None:
    """Release gates must not disappear under PYTHONOPTIMIZE / python -O."""
    if not condition:
        raise RuntimeError(message)


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
    source_tree = ast.parse(Path(__file__).read_text())
    require(not any(isinstance(node, ast.Assert) for node in ast.walk(source_tree)), "release smoke must use explicit failures, not optimized-away assertions")
    fixture = json.loads((REPO / "tests/fixtures/full-profile/package.json").read_text())
    overrides = fixture["pnpm"]["overrides"]
    require(len(overrides) == 293, "full-profile override count changed")
    require(CLI.is_file(), "install the locked full-profile fixture before this smoke")
    with tempfile.TemporaryDirectory(prefix="dsh-oidc-public-install-") as scratch:
        root = Path(scratch)
        home = root / "home"
        env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "LANG", "TMPDIR", "CI", "COREPACK_HOME") if k in os.environ}
        env.update(DSH_HOME=str(home), DSH_TELEMETRY_DISABLED="1", HOME=str(root / "user"), XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"), XDG_CACHE_HOME=str(root / "cache"), COREPACK_DEFAULT_TO_LATEST="0")
        require(run(["corepack", "pnpm@10.34.5", "--version"], root, env) == "10.34.5", "wrong package manager")
        run([str(CLI), "--profile", "web-oidc", "--from-default-profile", "web", "--dump-config"], root, env)
        profile = home / "profiles/web-oidc"
        manifest = profile / "package.json"
        package = json.loads(manifest.read_text())
        require(package["name"] == "dsh-profile-web-oidc", "wrong isolated profile")
        require(not package.get("dependencies") and not package.get("pnpm"), "profile already customized")
        package["packageManager"] = "pnpm@10.34.5"
        package["pnpm"] = {"overrides": overrides}
        manifest.write_text(json.dumps(package, indent=2) + "\n")
        manifest.chmod(0o600)
        tarball = run(["npm", "pack", "--silent", "--pack-destination", scratch], REPO, env).splitlines()[-1]
        run([str(CLI), "plugin", "--profile", "web-oidc", "add", "--save-exact", f"file:{root / tarball}"], root, env)
        run([str(CLI), "plugin", "--profile", "web-oidc", "add", "--save-exact", *(f"{name}@{version}" for name, version in PEERS.items())], root, env)
        shutil.rmtree(profile / "node_modules")
        run(["corepack", "pnpm@10.34.5", "--dir", str(profile), "install", "--frozen-lockfile", "--offline"], root, env)
        print(run(["node", str(REPO / "scripts/attest-install.mjs"), str(REPO / "tests/fixtures/full-profile"), str(profile)], root, env))
        audit = json.loads(run(["corepack", "pnpm@10.34.5", "--dir", str(profile), "audit", "--json"], root, env))
        require(sum(audit["metadata"]["vulnerabilities"].values()) == 0, "profile audit has vulnerabilities")
        print("installed profile audit: zero vulnerabilities")
        patch = profile / "cordis.patch.yml"
        uncommented = [line.strip() for line in patch.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        require(uncommented == ["[]"], "refusing to replace a customized profile patch")
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
        require("senti100-oidc" in dump and "DSH_OIDC_CLIENT_SECRET_REF" in dump, "public patch not loaded")
        require(synthetic_secret not in dump, "synthetic credential appeared in config output")
        installed = json.loads(manifest.read_text())["dependencies"]
        require(installed["@senti100/dsh-oidc"].startswith("file:"), "plugin was not installed from local tarball")
        require(all(installed[name] == version for name, version in PEERS.items()), "exact 0.2.0-rc.2 peers not installed")
        # Check actual resolution, not just dependency strings (stale symlinks can disagree).
        resolution = run(["node", "--input-type=module", "-e", """
import { createRequire } from 'node:module';
import { readFileSync, realpathSync } from 'node:fs';
const root = createRequire(process.cwd() + '/package.json');
const plugin = createRequire(root.resolve('@senti100/dsh-oidc/package.json'));
const names = JSON.parse(process.argv[1]);
console.log(JSON.stringify(Object.fromEntries(names.map(name => {
  const path = plugin.resolve(name + '/package.json');
  return [name, { version: JSON.parse(readFileSync(path)).version, path: realpathSync(path) }];
}))));
""", json.dumps(list(PEERS))], profile, env)
        resolved = json.loads(resolution)
        require(all(resolved[name]["version"] == version for name, version in PEERS.items()), "effective runtime peer mismatch")
        require(all(Path(item["path"]).is_relative_to(home) for item in resolved.values()), "peer symlink escaped disposable home")

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
        require(admitted, "OIDC auth-check route did not become ready (startup output withheld)")
        require(b"/?token=" not in output, "native bootstrap bearer URL printed despite the public patch")
        require(child.poll() is not None, "disposable DSH process survived termination")
        require(not check_route(port), "disposable DSH listener survived termination")
    print("public web-oidc install PASS: 293 overrides, exact 0.2.0-rc.2 peers, auth-check 401, no printed bearer URL, clean teardown")


if __name__ == "__main__":
    main()
