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
from typing import Any, AsyncIterator, Iterable, Iterator, Mapping, Sequence

import yaml

__version__ = "0.8.0"

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

# A master key is identified by (backend, normalized identifier).
Key = tuple[str, str]

# Where each backend stores its identifier in a file's `sops:` metadata block.
META_FIELD = {
    "age": "recipient",
    "pgp": "fp",
    "kms": "arn",
    "gcp_kms": "resource_id",
    "hckms": "key_id",
    "azure_keyvault": "vaultUrl",
    "hc_vault_transit_uri": "uri",
}

# File states, named after the sops command that would fix them.
STATE_ENCRYPTED = "encrypted"
STATE_PLAIN = "not encrypted"
STATE_UPDATEKEYS = "need updatekeys"
STATE_ROTATE = "need rotate"
STATE_ERROR = "error"

STATE_COLOR = {
    STATE_ENCRYPTED: "green",  # no drift
    STATE_PLAIN: None,  # no encryption -> default (white)
    STATE_UPDATEKEYS: "yellow",  # pure-plus drift: encryption has an extra key
    STATE_ROTATE: "yellow",  # minus drift: an expected key is missing
    STATE_ERROR: "red",
}
PORCELAIN_CODE = {
    STATE_ENCRYPTED: "E",
    STATE_PLAIN: "U",
    STATE_UPDATEKEYS: "-",
    STATE_ROTATE: "+",
    STATE_ERROR: "!",
}
LABEL_WIDTH = max(len(state) for state in STATE_COLOR)

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

    def keys(self) -> set[Key]:
        """The master keys this rule expects a file to be encrypted to."""
        return _keys_from_fields(self.fields)


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
# master keys
# --------------------------------------------------------------------------- #
def _normalize_key(backend: str, value: str) -> str:
    value = value.strip()
    if backend == "age":
        return value.lower()
    if backend == "pgp":
        return value.replace(" ", "").upper()
    return value


def _as_list(value: Any) -> list[str]:
    """sops accepts either a comma-separated string or a list for key fields."""
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _keys_from_fields(fields: Mapping[str, Any]) -> set[Key]:
    """The master keys a creation rule expects (top-level fields + key_groups)."""
    keys: set[Key] = set()
    for backend in BACKENDS:
        for value in _as_list(fields.get(backend)):
            keys.add((backend, _normalize_key(backend, value)))
    for group in fields.get("key_groups") or []:
        if isinstance(group, Mapping):
            keys |= _keys_from_fields(group)
    return keys


def _actual_keys(path: Path) -> set[Key] | None:
    """Master keys a file is actually encrypted to, from its plaintext metadata.

    Returns ``None`` when the format cannot be introspected (e.g. binary).
    """
    if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, Mapping):
        return None
    block = data.get("sops")
    if not isinstance(block, Mapping):
        return None

    keys: set[Key] = set()
    for backend in BACKENDS:
        entries = block.get(backend)
        if entries is None:
            continue
        for entry in entries if isinstance(entries, list) else [entries]:
            if isinstance(entry, Mapping):
                value = entry.get(META_FIELD[backend])
                if value is None:
                    continue
            else:
                value = entry
            keys.add((backend, _normalize_key(backend, str(value))))
    return keys


def _pronouns(keys: Iterable[Key]) -> dict[Key, str]:
    """Assign unnamed keys a `backend~index` pronoun, numbered per backend."""
    counters: dict[str, int] = {}
    result: dict[Key, str] = {}
    for backend, identifier in sorted(set(keys)):
        index = counters.get(backend, 0)
        counters[backend] = index + 1
        result[(backend, identifier)] = f"{backend}~{index}"
    return result


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


def _paint(text: str, color: str | None, enabled: bool) -> str:
    if not enabled or color is None:
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

        async def inspect(path: Path) -> tuple[bool | None, str | None, set[Key] | None]:
            async with limit:
                encrypted, error = await filestatus(path, sops)
                actual = None
                if error is None and encrypted:
                    actual = await asyncio.to_thread(_actual_keys, path)
            return encrypted, error, actual

        results = await asyncio.gather(*(inspect(path) for path, _rule in matches))

        entries = [
            _status_entry(config, path, rule, encrypted, error, actual, args)
            for (path, rule), (encrypted, error, actual) in zip(matches, results)
        ]

        if args.porcelain:
            for entry in entries:
                print(f"{PORCELAIN_CODE[entry.state]}\t{entry.path}")
            return 0

        _print_status(entries, config.root if args.branch else None)
        return 0


@dataclass
class StatusEntry:
    """One file's report: its state plus the keys it has and the rule expects."""

    path: str
    state: str
    keys: set[Key]
    expected: set[Key]
    extra: set[Key]
    missing: set[Key]
    unknown: bool
    error: str | None


def _status_entry(
    config: Config,
    path: Path,
    rule: Rule,
    encrypted: bool | None,
    error: str | None,
    actual: set[Key] | None,
    args: argparse.Namespace,
) -> StatusEntry:
    expected = rule.keys()
    display = _display(config, path, args)

    if error is not None:
        return StatusEntry(display, STATE_ERROR, set(), expected, set(), set(), True, error)
    if not encrypted:
        return StatusEntry(display, STATE_PLAIN, set(), expected, set(), set(expected), False, None)
    if actual is None:
        return StatusEntry(display, STATE_ENCRYPTED, set(), expected, set(), set(), True, None)

    extra, missing = actual - expected, expected - actual
    if missing:
        # A missing key shows as a red `-`: the file needs rotating.
        state = STATE_ROTATE
    elif extra:
        # Only extra keys (all pure-green `+`): needs updatekeys.
        state = STATE_UPDATEKEYS
    else:
        state = STATE_ENCRYPTED
    return StatusEntry(display, state, actual, expected, extra, missing, False, None)


def _key_tokens(entry: StatusEntry, pronouns: Mapping[Key, str]) -> list[tuple[str, str | None]]:
    """Diff the file's keys against the rule's: white same, green `+` extra, red `-` missing."""
    if entry.unknown:
        return [("?", None)]
    tokens: list[tuple[str, str | None]] = []
    for key in sorted(entry.keys | entry.expected):
        pronoun = pronouns[key]
        if key in entry.keys and key in entry.expected:
            tokens.append((pronoun, None))  # matches .sops.yaml -> white
        elif key in entry.keys:
            tokens.append((f"+{pronoun}", "green"))  # extra vs .sops.yaml
        else:
            tokens.append((f"-{pronoun}", "red"))  # missing vs .sops.yaml
    return tokens or [("-", None)]


def _print_status(entries: Sequence[StatusEntry], branch_root: Path | None = None) -> None:
    pronouns = _pronouns(key for entry in entries for key in entry.keys | entry.expected)

    if pronouns:
        # Unnamed keys get a `backend~index` pronoun; define them up top.
        for key in sorted(pronouns):
            print(f"{pronouns[key]}: {key[1]}")
        print()

    if branch_root is not None:
        print(f"## {branch_root}")

    color = sys.stdout.isatty()
    tokens = [_key_tokens(entry, pronouns) for entry in entries]
    plain_keys = [" ".join(text for text, _shade in row) for row in tokens]
    width_path = max((len(entry.path) for entry in entries), default=0)
    width_keys = max((len(text) for text in plain_keys if text != "-"), default=0)

    for entry, row, plain in zip(entries, tokens, plain_keys):
        label = _paint(entry.state.ljust(LABEL_WIDTH), STATE_COLOR[entry.state], color)
        line = f"{label}  {entry.path.ljust(width_path)}"
        if width_keys:
            colored = " ".join(_paint(text, shade, color) if shade else text for text, shade in row)
            line += f"  {colored}{' ' * (width_keys - len(plain))}"
        line = line.rstrip()
        if entry.error is not None:
            line += f"  {entry.error}"
        print(line)


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
