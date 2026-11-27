#!/usr/bin/env python3
"""Check the example and load all three generated providers with Mihomo."""

import argparse
import http.client
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from update_rules import CATEGORIES, ROOT, validate_output


class LocalController(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=2)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def loaded_counts(controller):
    client = LocalController(controller)
    try:
        client.request("GET", "/providers/rules")
        response = client.getresponse()
        if response.status != 200:
            raise ValueError(f"Mihomo API returned HTTP {response.status}")
        providers = json.load(response)["providers"]
        return {name: provider["ruleCount"] for name, provider in providers.items()}
    finally:
        client.close()


def verify(binary):
    config = yaml.safe_load((ROOT / "clash-example.yaml").read_text(encoding="utf-8"))
    config["proxy-groups"] = [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}]
    with tempfile.TemporaryDirectory(prefix="mrs-", dir="/tmp") as tmp:
        home = Path(tmp)
        config_path = home / "config.yaml"
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        command = [str(binary), "-d", str(home), "-f", str(config_path)]
        subprocess.run([*command, "-t"], check=True, timeout=30)

        expected = {}
        for category in CATEGORIES:
            source = ROOT / "rules" / f"{category}.yaml"
            expected[category] = validate_output(source)
            provider = config["rule-providers"][category]
            provider["type"] = "file"
            provider.pop("url")
            provider.pop("interval")
            target = home / provider["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        controller = home / "controller.sock"
        config["external-controller-unix"] = str(controller)
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        log_path = home / "mihomo.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                counts = {}
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        counts = loaded_counts(controller)
                    except (OSError, http.client.HTTPException, ValueError):
                        pass
                    if counts == expected:
                        break
                    time.sleep(0.2)
                log_text = log_path.read_text(encoding="utf-8")
                if counts != expected or "level=error" in log_text or "level=fatal" in log_text:
                    raise RuntimeError(f"expected {expected}, Mihomo loaded {counts}\n{log_text}")
                print(f"Mihomo loaded all provider rules: {counts}")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    verify(parser.parse_args().binary.resolve())
