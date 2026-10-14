#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["PyYAML>=6.0"]
# ///
"""sops-tool: a tiny, git-style front-end for sops.

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
  encrypt    encrypt matched, not-yet-encrypted files in place
  decrypt    decrypt matched files in place (a thin `sops` wrapper)

`status` reports every matched file, its keys and its encryption state. With
`--decrypt-check` it also runs `sops --decrypt` on each encrypted file and marks
the ones that open with an orange `*` (naming the matching keys where it can).
`decrypt` does not share that view: it is a thin wrapper that simply runs
`sops --decrypt` on the matched files and reports what sops says.

Commands accept `--` before paths, like git: `sops-tool status -- secrets/`.
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
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator, Mapping, Sequence

import yaml

__version__ = "0.20.0"

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
STATE_DECRYPTED = "decrypted"

STATE_COLOR = {
    STATE_ENCRYPTED: "green",  # no drift
    STATE_PLAIN: None,  # no encryption -> default (white)
    STATE_UPDATEKEYS: "yellow",  # pure-plus drift: encryption has an extra key
    STATE_ROTATE: "yellow",  # minus drift: an expected key is missing
    STATE_ERROR: "red",
    STATE_DECRYPTED: "green",
}
PORCELAIN_CODE = {
    STATE_ENCRYPTED: "E",
    STATE_PLAIN: "U",
    STATE_UPDATEKEYS: "+",
    STATE_ROTATE: "-",
    STATE_ERROR: "!",
    STATE_DECRYPTED: "D",
}
LABEL_WIDTH = max(len(state) for state in STATE_COLOR)

ANSI = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "orange": "\033[38;5;208m",
}


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

    def __init__(
        self,
        path: Path,
        rules: Sequence[Rule],
        key_names: Mapping[Key, str] | None = None,
    ) -> None:
        self.path = Path(path).resolve()
        self.root = self.path.parent
        self.rules = tuple(rules)
        self.key_names = dict(key_names or {})

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
        text = await asyncio.to_thread(_read_text, path)
        data = _parse_config(path, text)
        rules = _parse_rules(path, data.get("creation_rules"))
        key_names = _rule_key_names(rules, _raw_key_names(text, data))
        return cls(path, rules, key_names)

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


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def _parse_config(path: Path, text: str) -> Mapping[str, Any]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigError(f"{path}: expected a YAML mapping at the top level")
    return data


def _raw_key_names(text: str, data: Mapping[str, Any]) -> dict[str, str]:
    """Map a key's raw value to its name, from the `keys:` map and YAML anchors.

    Both of these let a `.sops.yaml` give keys human names::

        keys:
          admin: &admin age1...
        creation_rules:
          - age: *admin
    """
    names: dict[str, str] = {}
    keys_section = data.get("keys")
    if isinstance(keys_section, Mapping):
        for name, value in keys_section.items():
            for raw in _as_list(value):
                names.setdefault(raw, str(name))
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.ScalarEvent) and event.anchor and event.value is not None:
                names.setdefault(event.value, event.anchor)
    except yaml.YAMLError:
        pass
    return names


def _iter_rule_keys(fields: Mapping[str, Any]) -> Iterator[tuple[str, str]]:
    """Yield `(backend, raw_value)` for every key a rule references."""
    for backend in BACKENDS:
        for raw in _as_list(fields.get(backend)):
            yield backend, raw
    for group in fields.get("key_groups") or []:
        if isinstance(group, Mapping):
            yield from _iter_rule_keys(group)


def _rule_key_names(rules: Sequence[Rule], raw_names: Mapping[str, str]) -> dict[Key, str]:
    names: dict[Key, str] = {}
    for rule in rules:
        for backend, raw in _iter_rule_keys(rule.fields):
            name = raw_names.get(raw)
            if name:
                names.setdefault((backend, _normalize_key(backend, raw)), name)
    return names


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


def _is_read_error(message: str) -> bool:
    """True when sops failed to *read* the file, rather than to parse it."""
    lowered = message.lower()
    return "error reading file" in lowered or "permission denied" in lowered


async def _run_sops(
    config: "Config",
    sops: str,
    action: str,
    path: Path,
    env: Mapping[str, str] | None = None,
    in_place: bool = True,
) -> str | None:
    """Run `sops --config … --<action> [--in-place] <path>`. Returns an error."""
    command = [sops, "--config", str(config.path), f"--{action}"]
    if in_place:
        command.append("--in-place")
    command.append(str(path))
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_child_env(env),
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return _clean_error(stderr.decode(errors="replace"))
    return None


def _age_key_env(paths: Sequence[Path]) -> tuple[dict[str, str] | None, Path | None]:
    """Turn `--age-key-file`s into a `SOPS_AGE_KEY_FILE` env var.

    sops only reads a single identity file, so several are concatenated into a
    temporary one. Returns ``(env, temporary_file)``.
    """
    if not paths:
        return None, None
    if len(paths) == 1:
        return {"SOPS_AGE_KEY_FILE": str(paths[0])}, None
    text = "".join(path.read_text(encoding="utf-8") for path in paths)
    handle = tempfile.NamedTemporaryFile("w", prefix="sops-tool-age-", suffix=".txt", delete=False)
    handle.write(text)
    handle.close()
    temporary = Path(handle.name)
    return {"SOPS_AGE_KEY_FILE": str(temporary)}, temporary


def _child_env(env: Mapping[str, str] | None) -> dict[str, str] | None:
    return {**os.environ, **env} if env else None


AGE_KEY_ENV = "SOPS_AGE_KEY"
AGE_KEY_FILE_ENV = "SOPS_AGE_KEY_FILE"
AGE_KEY_CMD_ENV = "SOPS_AGE_KEY_CMD"


def _identity_texts(paths: Sequence[Path], include_env: bool) -> list[str]:
    """Age identity *material* from our key files and the `SOPS_AGE_KEY*` env.

    sops reads identities from many places; we mirror the ones that are plain
    text and can be named — `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE` and
    `SOPS_AGE_KEY_CMD`. An SSH key, a key command that refuses to run, or a key
    service simply yields nothing here; the `sops --decrypt` probe still covers
    them.
    """
    texts: list[str] = []

    def read(path: Path) -> None:
        try:
            texts.append(path.read_text(encoding="utf-8"))
        except OSError:
            pass

    for path in paths:
        read(path)
    if include_env:
        env_file = os.environ.get(AGE_KEY_FILE_ENV)
        if env_file:
            read(Path(env_file).expanduser())
        inline = os.environ.get(AGE_KEY_ENV)
        if inline:
            texts.append(inline)
        command = os.environ.get(AGE_KEY_CMD_ENV)
        if command:
            texts.append(_run_key_command(command))
    return texts


def _run_key_command(command: str) -> str:
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _age_recipients(texts: Iterable[str]) -> set[str]:
    """The age public keys hiding in identity material, however we can find them.

    `age-keygen -y` derives them properly from *any* identity (private key or
    identity file) — that is how an inline `SOPS_AGE_KEY`, which carries only
    secret keys, becomes a recipient we can name. The `# public key:` comments
    age-keygen writes are a fallback for when it is not installed.
    """
    blob = "\n".join(texts)
    if not blob.strip():
        return set()
    tool = shutil.which("age-keygen")
    if tool is not None:
        try:
            result = subprocess.run(
                [tool, "-y"], input=blob, capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None and result.returncode == 0:
            return set(re.findall(r"age1[0-9a-z]+", result.stdout))
    return set(re.findall(r"#\s*public key:\s*(age1[0-9a-z]+)", blob))


def _available_age_keys(key_files: Sequence[Path], include_env: bool = False) -> set[Key]:
    texts = _identity_texts(key_files, include_env)
    return {("age", recipient) for recipient in _age_recipients(texts)}


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

    The format is detected from the content, not the extension, so a sops file
    stored as JSON under an arbitrary name still resolves. Returns ``None`` when
    the file cannot be introspected (e.g. the binary store).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    # The file may be JSON (sops' fallback for unknown extensions, and it uses
    # tab indentation, which YAML rejects), or YAML. Try JSON first.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
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


def _resolve_key_files(args: argparse.Namespace) -> list[Path]:
    key_files = [_resolve(name, args) for name in args.age_key_file]
    for key_file in key_files:
        if not key_file.is_file():
            raise ConfigError(f"age key file not found: {key_file}")
    return key_files


def _display(config: Config, path: Path, args: argparse.Namespace) -> str:
    base = config.root if getattr(args, "full_name", False) else _base(args)
    return Path(os.path.relpath(path, base)).as_posix()


def _paint(text: str, color: str | None, enabled: bool) -> str:
    if not enabled or color is None:
        return text
    return f"{ANSI[color]}{text}{ANSI['reset']}"


def _paint_tokens(tokens: Sequence[tuple[str, str | None]], enabled: bool) -> str:
    return " ".join(_paint(text, shade, enabled) if shade else text for text, shade in tokens)


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
            help="machine-readable output: '<code>\\t<path>'",
        )
        parser.add_argument(
            "--full-name",
            action="store_true",
            help="show paths relative to the repository root",
        )
        parser.add_argument(
            "--decrypt-check",
            "-d",
            action="store_true",
            help="try to decrypt each file and mark the ones that open",
        )
        parser.add_argument(
            "--age-key-file",
            action="append",
            default=[],
            metavar="FILE",
            help="age identity file to check against (with --decrypt-check/-d; repeatable)",
        )

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = shutil.which("sops")
        if sops is None:
            print("sops-tool: sops not found in PATH", file=sys.stderr)
            return 127

        roots = [_resolve(path, args) for path in args.paths]
        key_files = _resolve_key_files(args)
        available = (
            _available_age_keys(key_files, include_env=True) if args.decrypt_check else set()
        )

        entries = await _collect_entries(config, roots, sops, args)
        if args.decrypt_check:
            await _mark_decryptable(config, sops, entries, key_files)

        if args.porcelain:
            for entry in entries:
                print(f"{PORCELAIN_CODE[entry.state]}\t{entry.path}")
            return 0

        _print_report(entries, config.key_names, available, config.root if args.branch else None)
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
    source: Path
    decryptable: bool = False


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

    if error is not None and _is_read_error(error):
        return StatusEntry(display, STATE_ERROR, set(), expected, set(), set(), True, error, path)
    if error is not None or not encrypted:
        # sops could not parse the file, or it simply is not encrypted: either
        # way it is not a sops document, so report it as plaintext.
        return StatusEntry(display, STATE_PLAIN, set(), expected, set(), set(expected), False, None, path)
    if actual is None:
        return StatusEntry(display, STATE_ENCRYPTED, set(), expected, set(), set(), True, None, path)

    extra, missing = actual - expected, expected - actual
    if extra:
        # The file carries a key the rule does not -> a red `-` -> rotate.
        state = STATE_ROTATE
    elif missing:
        # The rule wants a key the file lacks -> a green `+` -> updatekeys.
        state = STATE_UPDATEKEYS
    else:
        state = STATE_ENCRYPTED
    return StatusEntry(display, state, actual, expected, extra, missing, False, None, path)


async def _collect_entries(
    config: Config, roots: Sequence[Path], sops: str, args: argparse.Namespace
) -> list[StatusEntry]:
    """Inspect every matched file once, for both `status` and `decrypt`."""
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
    return [
        _status_entry(config, path, rule, encrypted, error, actual, args)
        for (path, rule), (encrypted, error, actual) in zip(matches, results)
    ]


async def _mark_decryptable(
    config: Config,
    sops: str,
    entries: Sequence[StatusEntry],
    key_files: Sequence[Path],
) -> None:
    """Try `sops --decrypt` on every encrypted entry and flag the ones that open.

    Naming is best-effort (see `_available_age_keys`); a key can also reach sops
    through sources we cannot enumerate — an SSH key, a key service, … — so the
    only honest test of "does this open?" is to ask sops.
    """
    decryptable = {STATE_ENCRYPTED, STATE_UPDATEKEYS, STATE_ROTATE}
    env, temporary = _age_key_env(key_files)
    limit = asyncio.Semaphore(MAX_CONCURRENCY)

    async def check(entry: StatusEntry) -> None:
        if entry.state not in decryptable:
            return
        async with limit:
            failure = await _run_sops(config, sops, "decrypt", entry.source, env, in_place=False)
        entry.decryptable = failure is None

    try:
        await asyncio.gather(*(check(entry) for entry in entries))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _key_tokens(entry: StatusEntry, labels: Mapping[Key, str]) -> list[tuple[str, str | None]]:
    """Diff the file's keys against the rule's: white same, green `+` extra, red `-` missing."""
    if entry.unknown:
        return [("?", None)]
    tokens: list[tuple[str, str | None]] = []
    for key in sorted(entry.keys | entry.expected, key=lambda key: labels.get(key, key[1])):
        label = labels.get(key, key[1])
        if key in entry.keys and key in entry.expected:
            tokens.append((label, None))  # matches .sops.yaml -> white
        elif key in entry.expected:
            tokens.append((f"+{label}", "green"))  # .sops.yaml has it, file lacks it
        else:
            tokens.append((f"-{label}", "red"))  # file has it, .sops.yaml lacks it
    return tokens or [("-", None)]


def _print_report(
    entries: Sequence[StatusEntry],
    key_names: Mapping[Key, str],
    available: set[Key],
    branch_root: Path | None = None,
) -> None:
    all_keys = {key for entry in entries for key in entry.keys | entry.expected} | set(available)
    pronouns = _pronouns(key for key in all_keys if key not in key_names)
    labels = {key: key_names.get(key) or pronouns[key] for key in all_keys}
    color = sys.stdout.isatty()

    if labels:
        # Named keys keep their name; unnamed ones get a `backend~index` pronoun;
        # the keys we can decrypt with are highlighted.
        for key in sorted(all_keys, key=lambda key: labels[key]):
            shade = "orange" if key in available else None
            print(_paint(f"{labels[key]}: {key[1]}", shade, color))
        print()

    if branch_root is not None:
        print(f"## {branch_root}")

    tokens = [_key_tokens(entry, labels) for entry in entries]
    matched = [
        [key for key in sorted(entry.keys, key=lambda key: labels[key]) if key in available]
        for entry in entries
    ]
    plain_keys = [" ".join(text for text, _shade in row) for row in tokens]
    plain_match = [
        " ".join(f"*{labels[key]}" for key in row) if row else ("*" if entry.decryptable else "")
        for entry, row in zip(entries, matched)
    ]
    width_path = max((len(entry.path) for entry in entries), default=0)
    width_keys = max((len(text) for text in plain_keys if text != "-"), default=0)
    width_match = max((len(text) for text in plain_match), default=0)

    for entry, row, plain, keys_used, match_plain in zip(
        entries, tokens, plain_keys, matched, plain_match
    ):
        label = _paint(entry.state.ljust(LABEL_WIDTH), STATE_COLOR[entry.state], color)
        line = f"{label}  {entry.path.ljust(width_path)}"
        if width_keys:
            colored = _paint_tokens(row, color)
            line += f"  {colored}{' ' * (width_keys - len(plain))}"
        if width_match:
            # Last column: `*name` for each of our keys that opens this file —
            # or a bare `*` when sops decrypts it through some other means.
            if keys_used:
                match = " ".join(_paint(f"*{labels[key]}", "orange", color) for key in keys_used)
            elif entry.decryptable:
                match = _paint("*", "orange", color)
            else:
                match = ""
            line += f"  {match}{' ' * (width_match - len(match_plain))}"
        line = line.rstrip()
        if entry.error is not None:
            line += f"  {entry.error}"
        print(line)


# --------------------------------------------------------------------------- #
# porcelain: encrypt / decrypt
# --------------------------------------------------------------------------- #
ENCRYPT_COLOR = {
    "encrypted": "green",
    "would encrypt": "yellow",
    "skipped": None,
    "error": "red",
}
DECRYPT_COLOR = {
    "decrypted": "green",
    "would decrypt": "yellow",
    "skipped": None,
    "error": "red",
}


def _emit_state(
    color: bool,
    width: int,
    palette: Mapping[str, str | None],
    state: str,
    path: str,
    detail: str | None = None,
) -> None:
    label = _paint(state.ljust(width), palette.get(state), color)
    print(f"{label}  {path}" + (f"  {detail}" if detail else ""))


async def _confirm(verb: str, display: str) -> bool:
    answer = await asyncio.to_thread(input, f"{verb} {display}? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _action_arguments(parser: argparse.ArgumentParser, verb: str) -> None:
    path_argument(parser, "limit to these paths")
    parser.add_argument("-n", "--dry-run", action="store_true", help=f"only show what would be {verb}ed")
    parser.add_argument("-i", "--interactive", action="store_true", help=f"confirm each file before {verb}ing")
    parser.add_argument("--full-name", action="store_true", help="show paths relative to the repository root")


@subcommand
class EncryptCommand(Subcommand):
    name = "encrypt"
    help = "encrypt, in place, every matched file that is not encrypted yet"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        _action_arguments(parser, "encrypt")

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = shutil.which("sops")
        if sops is None:
            print("sops-tool: sops not found in PATH", file=sys.stderr)
            return 127

        roots = [_resolve(path, args) for path in args.paths]
        matches = [entry async for entry in config.files(roots)]

        color = sys.stdout.isatty()
        width = max(len(state) for state in ENCRYPT_COLOR)
        acted = errors = 0

        for path, _rule in matches:
            display = _display(config, path, args)
            encrypted, error = await filestatus(path, sops)

            if error is not None and _is_read_error(error):
                _emit_state(color, width, ENCRYPT_COLOR, "error", display, error)
                errors += 1
                continue
            if encrypted:
                continue  # already a sops document
            if args.dry_run:
                _emit_state(color, width, ENCRYPT_COLOR, "would encrypt", display)
                acted += 1
                continue
            if args.interactive and not await _confirm("encrypt", display):
                _emit_state(color, width, ENCRYPT_COLOR, "skipped", display)
                continue

            failure = await _run_sops(config, sops, "encrypt", path)
            if failure is None:
                _emit_state(color, width, ENCRYPT_COLOR, "encrypted", display)
                acted += 1
            else:
                _emit_state(color, width, ENCRYPT_COLOR, "error", display, failure)
                errors += 1

        if acted == 0 and errors == 0:
            print("nothing to encrypt")
        return 1 if errors else 0


@subcommand
class DecryptCommand(Subcommand):
    name = "decrypt"
    help = "decrypt, in place, every matched file that is encrypted"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        _action_arguments(parser, "decrypt")
        parser.add_argument(
            "--age-key-file",
            action="append",
            default=[],
            metavar="FILE",
            help="age identity file to decrypt with (repeatable)",
        )

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = shutil.which("sops")
        if sops is None:
            print("sops-tool: sops not found in PATH", file=sys.stderr)
            return 127

        roots = [_resolve(path, args) for path in args.paths]
        key_files = _resolve_key_files(args)
        env, temporary = _age_key_env(key_files)
        try:
            matches = [entry async for entry in config.files(roots)]

            color = sys.stdout.isatty()
            width = max(len(state) for state in DECRYPT_COLOR)
            acted = errors = 0

            for path, _rule in matches:
                display = _display(config, path, args)
                encrypted, error = await filestatus(path, sops)
                if error is not None or not encrypted:
                    continue  # unreadable, or already plaintext

                if not args.dry_run and args.interactive and not await _confirm("decrypt", display):
                    _emit_state(color, width, DECRYPT_COLOR, "skipped", display)
                    continue

                # Always try, and report verbatim what sops says: this command is a
                # thin wrapper, not a "smart" filter.
                failure = await _run_sops(config, sops, "decrypt", path, env, in_place=not args.dry_run)
                if failure is None:
                    state = "would decrypt" if args.dry_run else "decrypted"
                    _emit_state(color, width, DECRYPT_COLOR, state, display)
                    acted += 1
                else:
                    _emit_state(color, width, DECRYPT_COLOR, "error", display, failure)
                    errors += 1

            if acted == 0 and errors == 0:
                print("nothing to decrypt")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return 1 if errors else 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sops-tool",
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
        return await args.command.run(config, args)
    except ConfigError as exc:
        print(f"sops-tool: {exc}", file=sys.stderr)
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
