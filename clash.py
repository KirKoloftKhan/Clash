#!/usr/bin/env python3
"""
Generate both SubZ and Sub-Win Clash profiles from a single source YAML file.

Example:
    python clash.py C:/path/to/clash.yaml
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - intentional fail-fast
    raise SystemExit("PyYAML is required to run this script.") from exc


PRIMARY_GROUP = "\U0001F506 LIST"  # dY"+ LIST
SELECT_GROUP = "\U0001F530 Select"  # dY"� Select
AUTO_GROUP = "AUTO \u267B\ufe0f"  # AUTO �T��,?
FALLBACK_GROUP = "Auto-Fallback"
TEST_URL = "http://www.gstatic.com/generate_204"


class RelaxedLoader(yaml.SafeLoader):
    """Safe loader that silently accepts unknown YAML tags."""


def _construct_unknown(  # type: ignore[override]
    loader: RelaxedLoader, node: yaml.Node
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    raise yaml.constructor.ConstructorError(  # pragma: no cover - defensive
        None, None, f"Cannot construct node type {type(node)}", node.start_mark
    )


RelaxedLoader.add_constructor(None, _construct_unknown)


INVISIBLE_CHARS = {
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202d",
    "\u202e",
    "\u200e",
    "\u200f",
}


def sanitize_path(value: str) -> str:
    cleaned = value.strip().strip('"').strip("'")
    cleaned = "".join(ch for ch in cleaned if ch not in INVISIBLE_CHARS)
    return os.path.expandvars(cleaned)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a Clash YAML file into SubZ.yml and Sub-Win.yml."
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path to the source clash.yaml file (prompted if omitted)",
    )
    parser.add_argument(
        "-z",
        "--subz-output",
        dest="subz_output",
        help="Destination path for SubZ.yml (defaults next to this script)",
    )
    parser.add_argument(
        "-w",
        "--subwin-output",
        dest="subwin_output",
        help="Destination path for Sub-Win.yml (defaults next to this script)",
    )
    return parser.parse_args()


def read_clash_config(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = path.read_text(encoding="utf-8", errors="ignore")

    try:
        data = yaml.load(raw, Loader=RelaxedLoader)
    except yaml.YAMLError as exc:
        raise SystemExit(f"Failed to parse {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise SystemExit(f"{path} does not contain a valid Clash mapping.")
    return data


def collect_proxies(entries: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    skipped = 0
    for entry in entries:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            skipped += 1
            continue
        proxies.append(entry)
        names.append(name)

    if not proxies:
        raise SystemExit("No usable proxies were found in the source config.")
    if skipped:
        print(f"Skipped {skipped} malformed proxy entries.", file=sys.stderr)
    return proxies, names


def build_subz_config(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "Global",
        "log-level": "silent",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["94.140.14.14", "94.140.15.15"],
        },
        "tun": {
            "enable": True,
            "stack": "gvisor",
            "dns-hijack": ["198.18.0.2:53"],
            "auto-route": True,
            "auto-detect-interface": True,
            "fallback": ["94.140.14.14", "94.140.14.15"],
        },
        "proxies": proxies,
    }


def build_subwin_config(
    proxies: list[dict[str, Any]], proxy_names: list[str]
) -> dict[str, Any]:
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "Global",
        "log-level": "silent",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["94.140.14.14", "94.140.15.15"],
        },
        "tun": {
            "enable": True,
            "stack": "gvisor",
            "dns-hijack": ["198.18.0.2:53"],
            "auto-route": True,
            "auto-detect-interface": True,
            "fallback": ["94.140.14.14", "94.140.14.15"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": PRIMARY_GROUP,
                "type": "select",
                "proxies": [AUTO_GROUP, SELECT_GROUP],
            },
            {"name": SELECT_GROUP, "type": "select", "proxies": proxy_names},
            {
                "name": AUTO_GROUP,
                "type": "url-test",
                "proxies": proxy_names,
                "url": TEST_URL,
                "interval": 300,
            },
            {
                "name": FALLBACK_GROUP,
                "type": "fallback",
                "proxies": proxy_names,
                "url": TEST_URL,
                "interval": 300,
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,ad.com,REJECT",
            "GEOIP,IR,DIRECT",
            f"MATCH,{PRIMARY_GROUP}",
            f"IP-CIDR,8.8.8.8/32,{PRIMARY_GROUP}",
            f"IP-CIDR,8.8.4.4/32,{PRIMARY_GROUP}",
            f"IP-CIDR,1.1.1.1/32,{PRIMARY_GROUP}",
            f"IP-CIDR,1.0.0.1/32,{PRIMARY_GROUP}",
            "SRC-IP-CIDR,192.168.1.201/32,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
        ],
    }


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.dump(
            data,
            handle,
            Dumper=yaml.SafeDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def main() -> None:
    args = parse_args()
    source_str = args.source
    if not source_str:
        try:
            source_str = input("Enter path to clash YAML file: ")
        except EOFError:
            source_str = ""
    if not source_str:
        raise SystemExit("No source file path provided.")

    source_clean = sanitize_path(source_str)
    if not source_clean:
        raise SystemExit("No source file path provided.")

    source = Path(source_clean).expanduser().resolve()
    if not source.is_file():
        raise SystemExit(f"Source file not found: {source}")

    script_dir = Path(__file__).resolve().parent
    subz_path = (
        Path(args.subz_output).expanduser().resolve()
        if args.subz_output
        else script_dir / "SubZ.yml"
    )
    subwin_path = (
        Path(args.subwin_output).expanduser().resolve()
        if args.subwin_output
        else script_dir / "Sub-Win.yml"
    )
    subz_path.parent.mkdir(parents=True, exist_ok=True)
    subwin_path.parent.mkdir(parents=True, exist_ok=True)

    config = read_clash_config(source)
    proxies_raw = config.get("proxies")
    if not isinstance(proxies_raw, list):
        raise SystemExit("The source config must contain a 'proxies' list.")

    proxies, proxy_names = collect_proxies(proxies_raw)

    write_yaml(subz_path, build_subz_config(proxies))
    write_yaml(subwin_path, build_subwin_config(proxies, proxy_names))

    print(
        f"Generated {subz_path} and {subwin_path} with {len(proxies)} proxies "
        f"based on {source.name}."
    )


if __name__ == "__main__":
    main()
