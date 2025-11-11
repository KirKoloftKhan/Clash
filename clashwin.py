#!/usr/bin/env python3
"""
Convert a generic Clash config into the trimmed-down Sub-Win flavour.

Example:
    python clashwin.py C:/path/to/clash.yaml
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - makes intent explicit
    raise SystemExit("PyYAML is required to run this script.") from exc


PRIMARY_GROUP = "\U0001F506 LIST"  # 🔆 LIST
SELECT_GROUP = "\U0001F530 Select"  # 🔰 Select
AUTO_GROUP = "AUTO \u267B\ufe0f"  # AUTO ♻️
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


INVISIBLE_CHARS = {  # control characters often copied from browsers
    "\ufeff",  # BOM
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202d",  # LRO
    "\u202e",  # RLO
    "\u200e",  # LRM
    "\u200f",  # RLM
}


def sanitize_path(value: str) -> str:
    cleaned = value.strip().strip('"').strip("'")
    cleaned = "".join(ch for ch in cleaned if ch not in INVISIBLE_CHARS)
    # Allow environment variables like %USERPROFILE% on Windows.
    cleaned = os.path.expandvars(cleaned)
    return cleaned


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a Clash YAML file into Sub-Win format."
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path to the source clash.yaml file (prompted if omitted)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Destination file (defaults to Sub-Win.yml next to this script)",
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


def build_output(proxies: list[dict[str, Any]], proxy_names: list[str]) -> dict[str, Any]:
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
            "nameserver": ["94.140.14.14", "94.140.14.15"],
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

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else Path(__file__).resolve().with_name("Sub-Win.yml")
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    config = read_clash_config(source)
    proxies_raw = config.get("proxies")
    if not isinstance(proxies_raw, list):
        raise SystemExit("The source config must contain a 'proxies' list.")

    proxies: list[dict[str, Any]] = []
    proxy_names: list[str] = []
    skipped = 0
    for entry in proxies_raw:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            skipped += 1
            continue
        proxies.append(entry)
        proxy_names.append(name)

    if not proxies:
        raise SystemExit("No usable proxies were found in the source config.")

    if skipped:
        print(f"Skipped {skipped} malformed proxy entries.", file=sys.stderr)

    result = build_output(proxies, proxy_names)

    with output_path.open("w", encoding="utf-8") as handle:
        yaml.dump(
            result,
            handle,
            Dumper=yaml.SafeDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

    print(
        f"Generated {output_path} with {len(proxies)} proxies "
        f"based on {source.name}."
    )


if __name__ == "__main__":
    main()
