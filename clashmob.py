#!/usr/bin/env python3
"""
Convert a generic Clash config into the SubZ flavour used by the mobile client.

Example:
    python clashmob.py C:/path/to/clash.yaml
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
    return os.path.expandvars(cleaned)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a Clash YAML file into the SubZ mobile format."
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Path to the source clash.yaml file (prompted if omitted)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Destination file (defaults to SubZ.yml next to this script)",
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


def collect_proxies(entries: list[Any]) -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
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

    if not proxies:
        raise SystemExit("No usable proxies were found in the source config.")
    if skipped:
        print(f"Skipped {skipped} malformed proxy entries.", file=sys.stderr)
    return proxies


def build_mobile_config(proxies: list[dict[str, Any]]) -> dict[str, Any]:
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
        else Path(__file__).resolve().with_name("SubZ.yml")
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    config = read_clash_config(source)
    proxies_raw = config.get("proxies")
    if not isinstance(proxies_raw, list):
        raise SystemExit("The source config must contain a 'proxies' list.")

    proxies = collect_proxies(proxies_raw)
    result = build_mobile_config(proxies)

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
