#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["PyYAML>=6.0"]
# ///
"""easy-sops: a tiny, git-style front-end for sops.

Every command runs against a *repository*: the nearest `.sops.yaml` found by
walking up from the current directory. `-C DIR` starts the search (and resolves
relative path arguments) in `DIR`, just like `git -C`.

The `.sops.yaml` is loaded once into an in-memory `Config` object; all commands
are thin, asynchronous queries over it. Blocking work (filesystem walks, YAML
parsing) is pushed onto threads, while `sops` itself is driven as a real async
subprocess, so commands can fan out when they need to. Commands follow git's
porcelain/plumbing split:

plumbing
  root       print the repository root
  ls-rules   list creation rules
  ls-files   list files caught by a rule
  match      print the rule for a path

porcelain
  status     report whether matched files are encrypted

`status --porcelain` prints one `<code>\\t<path>` line per file, where the code
is `E` (encrypted), `U` (unencrypted) or `!` (error).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence

import yaml

__version__ = "0.3.0"

CONFIG_NAME = ".sops.yaml"
SKIP_DIRS = frozenset({".git", ".hg", ".svn", ".venv", "node_modules"})
MAX_CONCURRENCY = 8
BACKENDS = (
    "age",
    "pgp",
    "kms",
    "gcp_kms",
    "hckms",
    "azure_keyvault",
    "hc_vault_transit_uri",
)


class ConfigError(Exception):
    """Raised when no `.sops.yaml` can be found or it cannot be parsed."""


# --------------------------------------------------------------------------- #
# plumbing: the repository object
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    """One entry of `creation_rules`."""

    index: int
    path_regex: str
    pattern: re.Pattern[str] | None
    fields: Mapping[str, Any]

    def matches(self, relpath: str) -> bool:
        # An empty path_regex matches everything, like sops.
        return self.pattern is None or self.pattern.search(relpath) is not None

    @property
    def name(self) -> str:
        return f"#{self.index}"

    def backends(self) -> tuple[str, ...]:
        found = [name for name in BACKENDS if self.fields.get(name)]
        if self.fields.get("key_groups"):
            found.append("key_groups")
        return tuple(found)


class Config:
    """The parsed `.sops.yaml`, and the root every command works from."""

    def __init__(self, path: Path, rules: Sequence[Rule]) -> None:
        self.path = Path(path).resolve()
        self.root = self.path.parent
        self.rules = tuple(rules)

    # -- construction ------------------------------------------------------- #
    @classmethod
    async def discover(cls, start: Path | None = None) -> "Config":
        directory = (start or Path.cwd()).resolve()
        if directory.is_file():
            directory = directory.parent
        path = await asyncio.to_thread(_find_config, directory)
        if path is None:
            raise ConfigError(f"no {CONFIG_NAME} found in {directory} or any parent")
        return await cls.load(path)

    @classmethod
    async def load(cls, path: Path) -> "Config":
        path = Path(path).resolve()
        raw = await asyncio.to_thread(_read_config, path)
        return cls(path, _parse_rules(path, raw.get("creation_rules")))

    # -- queries ------------------------------------------------------------ #
    def relative(self, path: Path) -> str:
        """Path as sops sees it: relative to the repo root, slash-separated."""
        return Path(os.path.relpath(path, self.root)).as_posix()

    def match(self, relpath: str) -> Rule | None:
        """The first rule matching *relpath*, mirroring sops precedence."""
        for rule in self.rules:
            if rule.matches(relpath):
                return rule
        return None

    def rule_for(self, path: Path) -> Rule | None:
        return self.match(self.relative(Path(path).resolve()))

    async def files(self, roots: Sequence[Path] = ()) -> AsyncIterator[tuple[str, Path, Rule]]:
        """Yield `(relpath, path, rule)` for every file caught by a rule."""
        matched = await asyncio.to_thread(_matched_files, self, tuple(roots))
        for item in matched:
            yield item


def _find_config(directory: Path) -> Path | None:
    for candidate in (directory, *directory.parents):
        config = candidate / CONFIG_NAME
        if config.is_file():
            return config
    return None


def _read_config(path: Path) -> Mapping[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{path}: expected a YAML mapping at the top level")
    return raw


def _parse_rules(config: Path, raw: Any) -> list[Rule]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError(f"{config}: 'creation_rules' must be a list")
    rules: list[Rule] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            continue
        pattern = str(entry.get("path_regex") or "")
        try:
            compiled = re.compile(pattern) if pattern else None
        except re.error as exc:
            raise ConfigError(
                f"{config}: rule #{index}: invalid path_regex {pattern!r}: {exc}"
            ) from exc
        rules.append(Rule(index, pattern, compiled, entry))
    return rules


def _matched_files(config: Config, roots: Sequence[Path]) -> list[tuple[str, Path, Rule]]:
    result: list[tuple[str, Path, Rule]] = []
    for root in roots or (config.root,):
        for path in _walk(Path(root)):
            if path.name == CONFIG_NAME:
                continue
            relpath = config.relative(path)
            rule = config.match(relpath)
            if rule is not None:
                result.append((relpath, path, rule))
    return result


def _walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


async def filestatus(path: Path, sops: str) -> tuple[bool | None, str | None]:
    """Thin wrapper around `sops filestatus`: returns `(encrypted, error)`."""
    proc = await asyncio.create_subprocess_exec(
        sops,
        "filestatus",
        str(path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return None, _clean_error(stderr.decode(errors="replace"))
    text = stdout.decode(errors="replace")
    try:
        return bool(json.loads(text).get("encrypted")), None
    except (ValueError, AttributeError):
        return None, f"unexpected filestatus output: {text.strip()!r}"


def _clean_error(stderr: str) -> str:
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    if not lines:
        return "sops filestatus failed"
    match = re.search(r'msg="(.*)"\s*$', lines[-1])
    if not match:
        return lines[-1]
    return match.group(1).replace('\\"', '"').replace("\\n", " ").replace("\\\\", "\\")


# --------------------------------------------------------------------------- #
# plumbing commands
# --------------------------------------------------------------------------- #
async def cmd_root(config: Config, args: argparse.Namespace) -> int:
    print(config.root)
    return 0


async def cmd_ls_rules(config: Config, args: argparse.Namespace) -> int:
    for rule in config.rules:
        pattern = rule.path_regex or "*"
        backends = ",".join(rule.backends()) or "-"
        print(f"{rule.name}\t{pattern}\t{backends}")
    return 0


async def cmd_ls_files(config: Config, args: argparse.Namespace) -> int:
    roots = [_resolve(path, args.directory) for path in args.paths]
    async for relpath, _path, _rule in config.files(roots):
        print(relpath)
    return 0


async def cmd_match(config: Config, args: argparse.Namespace) -> int:
    rule = config.rule_for(_resolve(args.path, args.directory))
    if rule is None:
        return 1
    print(rule.name)
    return 0


# --------------------------------------------------------------------------- #
# porcelain commands
# --------------------------------------------------------------------------- #
async def cmd_status(config: Config, args: argparse.Namespace) -> int:
    sops = shutil.which("sops")
    if sops is None:
        print("easy-sops: sops not found in PATH", file=sys.stderr)
        return 127

    roots = [_resolve(path, args.directory) for path in args.paths]
    matches = [(relpath, path) async for relpath, path, _rule in config.files(roots)]

    limit = asyncio.Semaphore(MAX_CONCURRENCY)

    async def check(relpath: str, path: Path) -> tuple[str, bool | None, str | None]:
        async with limit:
            encrypted, error = await filestatus(path, sops)
        return relpath, encrypted, error

    entries = await asyncio.gather(*(check(relpath, path) for relpath, path in matches))

    if args.porcelain:
        for relpath, encrypted, error in entries:
            code = "!" if error else ("E" if encrypted else "U")
            print(f"{code}\t{relpath}")
        return 0

    _report([(relpath, encrypted, error) for relpath, encrypted, error in entries])
    return 0


def _report(entries: Sequence[tuple[str, bool | None, str | None]]) -> None:
    sections = {
        "Encrypted": [path for path, enc, err in entries if err is None and enc],
        "Not encrypted": [path for path, enc, err in entries if err is None and not enc],
        "Errors": [f"{path}: {err}" for path, _enc, err in entries if err],
    }
    first = True
    for title, items in sections.items():
        if not items:
            continue
        if not first:
            print()
        first = False
        print(f"{title}:")
        for item in items:
            print(f"  {item}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
Command = Callable[[Config, argparse.Namespace], Awaitable[int]]

COMMANDS: dict[str, Command] = {
    "root": cmd_root,
    "ls-rules": cmd_ls_rules,
    "ls-files": cmd_ls_files,
    "match": cmd_match,
    "status": cmd_status,
}


def _resolve(raw: str, base: str | None) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute() and base:
        path = Path(base) / path
    return path.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="easy-sops",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-C",
        dest="directory",
        metavar="DIR",
        help="run as if started in DIR (like git -C)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("root", help="print the repository root")
    sub.add_parser("ls-rules", help="list creation rules (name, path_regex, backends)")

    ls_files = sub.add_parser("ls-files", help="list files caught by a creation rule")
    ls_files.add_argument("paths", nargs="*", metavar="PATH")

    match = sub.add_parser("match", help="print the rule for PATH (exit 1 if none)")
    match.add_argument("path", metavar="PATH")

    status = sub.add_parser("status", help="report whether matched files are encrypted")
    status.add_argument("paths", nargs="*", metavar="PATH")
    status.add_argument(
        "--porcelain",
        action="store_true",
        help="machine-readable output: '<E|U|!>\\t<path>'",
    )
    return parser


async def run(args: argparse.Namespace) -> int:
    try:
        config = await Config.discover(Path(args.directory) if args.directory else None)
    except ConfigError as exc:
        print(f"easy-sops: {exc}", file=sys.stderr)
        return 2
    return await COMMANDS[args.command](config, args)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
