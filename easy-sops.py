#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["PyYAML>=6.0"]
# ///
"""easy-sops: a tiny, git-style front-end for sops.

Every command runs against a *repository*: the nearest `.sops.yaml` found by
walking up from the current directory. `-C DIR` starts the search (and resolves
relative path arguments) in `DIR`, just like `git -C`.

The `.sops.yaml` is loaded once into an in-memory `Config` object. Commands are
self-contained `Subcommand` classes: each defines its own arguments and its own
`run`, and registers itself with the `@subcommand` decorator. Blocking work
(directory walks, YAML parsing) runs on threads, while `sops` is driven as a
real async subprocess.

plumbing
  root       print the repository root
  ls-rules   list creation rules
  ls-files   list files caught by a rule
  match      print the rule for a path (exit 1 if none)

porcelain
  status     report whether matched files are encrypted

Commands accept `--` before paths, like git: `easy-sops status -- secrets/`.
Paths are printed relative to the current directory by default; pass
`--full-name` for repository-root-relative paths.
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
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence

import yaml

__version__ = "0.4.0"

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

# status -> (label, ansi color, porcelain code)
STATUS_STYLE = {
    "encrypted": ("encrypted", "green", "E"),
    "plain": ("not encrypted", "yellow", "U"),
    "error": ("error", "red", "!"),
}
LABEL_WIDTH = max(len(label) for label, _color, _code in STATUS_STYLE.values())

ANSI = {"reset": "\033[0m", "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m"}


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

    async def files(self, roots: Sequence[Path] = ()) -> AsyncIterator[tuple[Path, Rule]]:
        """Yield `(path, rule)` for every file caught by a rule."""
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


def _matched_files(config: Config, roots: Sequence[Path]) -> list[tuple[Path, Rule]]:
    result: list[tuple[Path, Rule]] = []
    for root in roots or (config.root,):
        for path in _walk(Path(root)):
            if path.name == CONFIG_NAME:
                continue
            rule = config.rule_for(path)
            if rule is not None:
                result.append((path, rule))
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
# path helpers
# --------------------------------------------------------------------------- #
def _base(args: argparse.Namespace) -> Path:
    """Directory that relative paths are interpreted and displayed against."""
    return Path(args.directory).expanduser().resolve() if args.directory else Path.cwd()


def _resolve(raw: str, args: argparse.Namespace) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute() and args.directory:
        path = Path(args.directory) / path
    return path.resolve()


def _display(config: Config, path: Path, args: argparse.Namespace) -> str:
    base = config.root if getattr(args, "full_name", False) else _base(args)
    return Path(os.path.relpath(path, base)).as_posix()


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI[color]}{text}{ANSI['reset']}"


# --------------------------------------------------------------------------- #
# subcommand framework
# --------------------------------------------------------------------------- #
class Subcommand:
    """A self-contained command: it defines its own arguments and behaviour."""

    name: str
    help: str

    def configure(self, parser: argparse.ArgumentParser) -> None:
        """Register this command as the parser's dispatch target."""
        parser.set_defaults(command=self)

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        raise NotImplementedError


REGISTRY: dict[str, Subcommand] = {}


def subcommand(cls: type[Subcommand]) -> type[Subcommand]:
    """Register a `Subcommand` subclass under its `name`."""
    REGISTRY[cls.name] = cls()
    return cls


def path_argument(parser: argparse.ArgumentParser, help: str) -> None:
    """Add the common trailing PATH argument (usable after `--`, like git)."""
    parser.add_argument("paths", nargs="*", metavar="PATH", help=help)


# --------------------------------------------------------------------------- #
# plumbing commands
# --------------------------------------------------------------------------- #
@subcommand
class RootCommand(Subcommand):
    name = "root"
    help = "print the repository root"

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        print(config.root)
        return 0


@subcommand
class LsRulesCommand(Subcommand):
    name = "ls-rules"
    help = "list creation rules (name, path_regex, backends)"

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        for rule in config.rules:
            pattern = rule.path_regex or "*"
            backends = ",".join(rule.backends()) or "-"
            print(f"{rule.name}\t{pattern}\t{backends}")
        return 0


@subcommand
class LsFilesCommand(Subcommand):
    name = "ls-files"
    help = "list files caught by a creation rule"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        path_argument(parser, "limit the listing to these paths")
        parser.add_argument(
            "--full-name",
            action="store_true",
            help="show paths relative to the repository root",
        )

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        roots = [_resolve(path, args) for path in args.paths]
        async for path, _rule in config.files(roots):
            print(_display(config, path, args))
        return 0


@subcommand
class MatchCommand(Subcommand):
    name = "match"
    help = "print the rule for a path (exit 1 if none)"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        parser.add_argument("path", metavar="PATH", help="path to look up")

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        rule = config.rule_for(_resolve(args.path, args))
        if rule is None:
            return 1
        print(rule.name)
        return 0


# --------------------------------------------------------------------------- #
# porcelain commands
# --------------------------------------------------------------------------- #
@subcommand
class StatusCommand(Subcommand):
    name = "status"
    help = "report whether matched files are encrypted"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        path_argument(parser, "limit the report to these paths")
        parser.add_argument("--branch", "-b", action="store_true", help="show the repository header")
        parser.add_argument(
            "--porcelain",
            action="store_true",
            help="machine-readable output: '<E|U|!>\\t<path>'",
        )
        parser.add_argument(
            "--full-name",
            action="store_true",
            help="show paths relative to the repository root",
        )

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = shutil.which("sops")
        if sops is None:
            print("easy-sops: sops not found in PATH", file=sys.stderr)
            return 127

        roots = [_resolve(path, args) for path in args.paths]
        matches = [entry async for entry in config.files(roots)]

        limit = asyncio.Semaphore(MAX_CONCURRENCY)

        async def check(path: Path) -> tuple[bool | None, str | None]:
            async with limit:
                return await filestatus(path, sops)

        results = await asyncio.gather(*(check(path) for path, _rule in matches))

        entries: list[tuple[str, str, str | None]] = []
        for (path, _rule), (encrypted, error) in zip(matches, results):
            if error is not None:
                state = "error"
            elif encrypted:
                state = "encrypted"
            else:
                state = "plain"
            entries.append((_display(config, path, args), state, error))

        if args.porcelain:
            for path, state, _error in entries:
                print(f"{STATUS_STYLE[state][2]}\t{path}")
            return 0

        color = sys.stdout.isatty()
        if args.branch:
            print(f"## {config.root}")
        for path, state, _error in entries:
            label, shade, _code = STATUS_STYLE[state]
            print(f"{_paint(label.ljust(LABEL_WIDTH), shade, color)}  {path}")

        for path, _state, error in entries:
            if error is not None:
                print(f"{path}: {error}", file=sys.stderr)
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
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

    subparsers = parser.add_subparsers(required=True)
    for command in REGISTRY.values():
        subparser = subparsers.add_parser(command.name, help=command.help)
        command.configure(subparser)
    return parser


async def run(args: argparse.Namespace) -> int:
    try:
        config = await Config.discover(Path(args.directory) if args.directory else None)
    except ConfigError as exc:
        print(f"easy-sops: {exc}", file=sys.stderr)
        return 2
    return await args.command.run(config, args)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
