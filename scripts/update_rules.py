#!/usr/bin/env python3
"""Generate classical YAML rule sets by category and as a combined list."""

import argparse
import ipaddress
import os
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("direct", "proxy", "reject")
PROVIDERS = (*CATEGORIES, "all")
DOMAIN = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
DOMAIN_WILDCARD = re.compile(r"[A-Za-z0-9_*?-]+(?:\.[A-Za-z0-9_*?-]+)*")
TRANSIENT_HTTP = {408, 429, 500, 502, 503, 504}
TIMEOUT = 30
ATTEMPTS = 3
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
Dumper = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


@dataclass(frozen=True)
class Source:
    name: str
    behavior: str
    url: str
    no_resolve: bool = False


def load_yaml(text):
    return yaml.load(text, Loader=Loader)


def load_sources(path):
    config = load_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != {"outputs"}:
        raise ValueError("sources.yaml must contain an outputs mapping")
    outputs = config["outputs"]
    if not isinstance(outputs, dict) or set(outputs) != set(CATEGORIES):
        raise ValueError("outputs must contain direct, proxy and reject")

    sources = {}
    for category in CATEGORIES:
        if not isinstance(outputs[category], list) or not outputs[category]:
            raise ValueError(f"{category}: expected a nonempty source list")
        sources[category] = []
        names = set()
        for entry in outputs[category]:
            if not isinstance(entry, dict) or set(entry) - {"name", "behavior", "url", "no-resolve"}:
                raise ValueError(f"{category}: invalid source definition: {entry!r}")
            name, behavior, url = (entry.get(key) for key in ("name", "behavior", "url"))
            flag = entry.get("no-resolve", False)
            if not isinstance(name, str) or not name.strip() or name in names:
                raise ValueError(f"{category}: source name must be nonempty and unique: {name!r}")
            if behavior not in ("domain", "ipcidr", "classical"):
                raise ValueError(f"{category}/{name}: unsupported behavior {behavior!r}")
            if not isinstance(url, str) or urlsplit(url).scheme != "https" or not urlsplit(url).netloc:
                raise ValueError(f"{category}/{name}: expected an HTTPS source URL")
            if not isinstance(flag, bool) or ("no-resolve" in entry and behavior != "ipcidr"):
                raise ValueError(f"{category}/{name}: no-resolve is a boolean for ipcidr sources only")
            names.add(name)
            sources[category].append(Source(name, behavior, url, flag))
    return sources


def download(url):
    request = Request(url, headers={"User-Agent": "clash-rules-simple/1"})
    for attempt in range(ATTEMPTS):
        try:
            with urlopen(request, timeout=TIMEOUT) as response:
                if response.status != 200:
                    raise ValueError(f"expected HTTP 200, received {response.status}")
                if response.headers.get_content_type() == "text/html":
                    raise ValueError("received HTML instead of YAML")
                data = response.read(MAX_DOWNLOAD_BYTES + 1)
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("source exceeds the download size limit")
                content_length = response.headers.get("Content-Length")
                if content_length is not None and len(data) != int(content_length):
                    raise HTTPException("incomplete response body")
                return data.decode("utf-8-sig")
        except HTTPError as error:
            error.close()
            if error.code not in TRANSIENT_HTTP or attempt == ATTEMPTS - 1:
                raise
        except (URLError, OSError, HTTPException):
            if attempt == ATTEMPTS - 1:
                raise
        time.sleep(2**attempt)
    raise AssertionError("download attempts exhausted")


def parse_payload(text, *, allow_empty=False):
    data = load_yaml(text)
    if not isinstance(data, dict) or set(data) != {"payload"}:
        raise ValueError("expected a YAML mapping containing only payload")
    payload = data["payload"]
    if payload is None and allow_empty:
        return []
    if not isinstance(payload, list) or (not payload and not allow_empty):
        raise ValueError("payload must be a nonempty list")
    if any(not isinstance(item, str) or not item or item != item.strip() or not item.isprintable() for item in payload):
        raise ValueError("payload entries must be nonempty printable strings without surrounding whitespace")
    return payload


def parse_cidr(value):
    address, separator, prefix = value.partition("/")
    if not separator or not re.fullmatch(r"[0-9]+", prefix) or "%" in address:
        raise ValueError(f"expected an IPv4 or IPv6 CIDR prefix: {value!r}")
    return ipaddress.ip_network(value)


def validate_classical(rule):
    parts = rule.split(",")
    if len(parts) < 2 or not parts[1] or parts[1] != parts[1].strip():
        raise ValueError(f"invalid classical rule: {rule!r}")
    kind, value, *params = parts
    if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        if params or not DOMAIN.fullmatch(value):
            raise ValueError(f"invalid {kind} rule: {rule!r}")
    elif kind == "DOMAIN-WILDCARD":
        if params or not DOMAIN_WILDCARD.fullmatch(value):
            raise ValueError(f"invalid {kind} rule: {rule!r}")
    elif kind in ("IP-CIDR", "IP-CIDR6"):
        expected_version = 4 if kind == "IP-CIDR" else 6
        if parse_cidr(value).version != expected_version or params not in ([], ["no-resolve"]):
            raise ValueError(f"invalid {kind} rule: {rule!r}")
    elif kind in ("PROCESS-NAME", "PROCESS-PATH"):
        if params:
            raise ValueError(f"invalid {kind} rule: {rule!r}")
    else:
        raise ValueError(f"unsupported classical rule type: {kind!r}")
    return rule


def read_custom_direct(path):
    try:
        payload = parse_payload(path.read_text(encoding="utf-8"), allow_empty=True)
        rules = set()
        for index, rule in enumerate(payload, 1):
            try:
                rules.add(validate_classical(rule))
            except ValueError as error:
                raise ValueError(f"payload entry {index}: {error}") from error
        return rules
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise ValueError(f"{path}: {error}") from error


def convert_rule(item, source):
    if source.behavior == "classical":
        return validate_classical(item)
    if source.behavior == "ipcidr":
        network = parse_cidr(item)
        kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        flag = ",no-resolve" if source.no_resolve else ""
        return f"{kind},{network}{flag}"

    domain = item.removeprefix("+.")
    if not DOMAIN.fullmatch(domain):
        raise ValueError(f"unsupported domain pattern: {item!r}")
    kind = "DOMAIN-SUFFIX" if item.startswith("+.") else "DOMAIN"
    return f"{kind},{domain.lower()}"


def collect_rules(sources):
    outputs = {}
    for category, entries in sources.items():
        merged = set()
        for source in entries:
            try:
                payload = parse_payload(download(source.url))
                for index, item in enumerate(payload, 1):
                    try:
                        merged.add(convert_rule(item, source))
                    except ValueError as error:
                        raise ValueError(f"payload entry {index}: {error}") from error
            except (ValueError, OSError, HTTPException, yaml.YAMLError) as error:
                raise ValueError(f"{category}/{source.name} ({source.url}): {error}") from error
            print(f"{category}/{source.name}: {len(payload):,} source entries", flush=True)
        outputs[category] = sorted(merged)
        print(f"{category}: {len(merged):,} unique rules", flush=True)
    return outputs


def read_output(path):
    payload = parse_payload(path.read_text(encoding="utf-8"))
    if any(a >= b for a, b in zip(payload, payload[1:])):
        raise ValueError(f"{path}: expected sorted, unique rules")
    for rule in payload:
        validate_classical(rule)
    return payload


def combined_rules(outputs):
    return sorted({rule for category in CATEGORIES for rule in outputs[category]})


def publish(outputs, directory):
    directory.mkdir(parents=True, exist_ok=True)
    outputs = {**outputs, "all": combined_rules(outputs)}
    filenames = [f"{name}.yaml" for name in PROVIDERS]
    with tempfile.TemporaryDirectory(prefix=".update-", dir=directory) as tmp:
        staging = Path(tmp)
        for name, filename in zip(PROVIDERS, filenames):
            text = yaml.dump({"payload": outputs[name]}, Dumper=Dumper, allow_unicode=True)
            path = staging / filename
            path.write_text(text, encoding="utf-8", newline="\n")
            read_output(path)

        # Keep a backup until every replacement succeeds. Git commits the outputs together.
        backups = {}
        for name in filenames:
            target = directory / name
            if target.exists():
                backups[name] = staging / f"{name}.bak"
                shutil.copy2(target, backups[name])
        replaced = []
        try:
            for name in filenames:
                os.replace(staging / name, directory / name)
                replaced.append(name)
        except OSError:
            for name in reversed(replaced):
                if name in backups:
                    os.replace(backups[name], directory / name)
                else:
                    (directory / name).unlink()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT / "sources.yaml")
    parser.add_argument("--custom-direct", type=Path, default=ROOT / "custom" / "direct.yaml")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "rules")
    parser.add_argument("--check", action="store_true", help="validate existing files without downloading")
    args = parser.parse_args()
    try:
        custom = read_custom_direct(args.custom_direct)
        if args.check:
            outputs = {}
            for name in PROVIDERS:
                path = args.output_dir / f"{name}.yaml"
                outputs[name] = read_output(path)
                print(f"{path.name}: {len(outputs[name]):,} valid rules")
            if outputs["all"] != combined_rules(outputs):
                raise ValueError("all.yaml must match the union of direct, proxy and reject")
            if not custom.issubset(outputs["direct"]):
                raise ValueError("direct.yaml is missing custom rules; regenerate the outputs")
        else:
            outputs = collect_rules(load_sources(args.sources))
            outputs["direct"] = sorted(custom.union(outputs["direct"]))
            print(f"direct/custom: {len(custom):,} custom rules; {len(outputs['direct']):,} total", flush=True)
            publish(outputs, args.output_dir)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"update-rules: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
