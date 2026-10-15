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
(directory walks, YAML parsing, age-key derivation) runs on threads, while `sops`
is driven as a real async subprocess.

The vocabulary every command shares:

* `Key`     — one master key, `(backend, identifier)`, normalised for comparison;
* `State`   — a labelled outcome, with its colour and porcelain code;
* `Inspection` — the single, uniform answer to "what is this file?": a `State`,
  the keys it is encrypted to (`None` when unknown), and an error message.

`sops` is only ever spoken to through the `Sops` driver, so the filestatus/decrypt
semantics live in exactly one place, and `Reporter` is the only thing that prints.

plumbing
  root       print the repository root
  ls-rules   list creation rules
  ls-files   list files caught by a rule
  match      print the rule for a path (exit 1 if none)

porcelain
  status     report whether matched files are encrypted
  encrypt    encrypt matched, not-yet-encrypted files in place
  decrypt    decrypt matched files in place (a thin `sops` wrapper)
  updatekeys reconcile matched files' keys with .sops.yaml
  rotate     sync a file's keys and generate a fresh data key

`status` reports every matched file, its keys and its encryption state. With
`--decrypt-check` (`-d`) it also runs `sops --decrypt` on each encrypted file and
marks the ones that open with an orange `*`, naming the matching keys where it
can. `decrypt` does not share that view: it is a thin wrapper that simply runs
`sops --decrypt` on the matched files and reports what sops says. `updatekeys`
runs `sops updatekeys` on the files whose keys drifted from `.sops.yaml` — the
`need updatekeys` ones by default, plus the `need rotate` ones with `--rotate`
(sops updatekeys reconciles both directions). `rotate` is the heavier fix for the
`need rotate` files: it syncs their keys and then rotates the data key.

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
from typing import Any, Collection, Iterable, Iterator, Mapping, Sequence

import yaml

__version__ = "0.22.0"

CONFIG_NAME = ".sops.yaml"
SKIP_DIRS = frozenset({".git", ".hg", ".svn", ".venv", "node_modules"})
MAX_CONCURRENCY = 8

# sops backends we understand, and where each stores its identifier in a file's
# `sops:` metadata block.
BACKENDS = (
    "age",
    "pgp",
    "kms",
    "gcp_kms",
    "hckms",
    "azure_keyvault",
    "hc_vault_transit_uri",
)
META_FIELD = {
    "age": "recipient",
    "pgp": "fp",
    "kms": "arn",
    "gcp_kms": "resource_id",
    "hckms": "key_id",
    "azure_keyvault": "vaultUrl",
    "hc_vault_transit_uri": "uri",
}

ANSI = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "orange": "\033[38;5;208m",
}


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #
class ToolError(Exception):
    """A user-facing failure; `code` is the process exit status."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


class ConfigError(ToolError):
    """The repository could not be found, read or parsed."""


# --------------------------------------------------------------------------- #
# vocabulary: keys, states, and the result of examining a file
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, order=True)
class Key:
    """One master key: a backend plus its normalised identifier."""

    backend: str
    identifier: str

    @classmethod
    def of(cls, backend: str, value: str) -> "Key":
        return cls(backend, _normalize_key(backend, value))

    @property
    def text(self) -> str:
        return self.identifier


@dataclass(frozen=True)
class State:
    """A labelled outcome: how it reads, how it is coloured, its porcelain code."""

    label: str
    color: str | None = None
    code: str = ""


# Inspection states (what a file *is*) and action states (what a command *did*).
ENCRYPTED = State("encrypted", "green", "E")
PLAIN = State("not encrypted", None, "U")
UPDATEKEYS = State("need updatekeys", "yellow", "+")
ROTATE = State("need rotate", "yellow", "-")
ERROR = State("error", "red", "!")
DECRYPTED = State("decrypted", "green", "D")
UPDATEDKEYS = State("updated keys", "green")
ROTATED = State("rotated", "green")
WOULD_ENCRYPT = State("would encrypt", "yellow")
WOULD_DECRYPT = State("would decrypt", "yellow")
WOULD_UPDATEKEYS = State("would update", "yellow")
WOULD_ROTATE = State("would rotate", "yellow")
SKIPPED = State("skipped", None)

# A file in one of these states has encrypted keys we might be able to open.
ENCRYPTED_STATES = (ENCRYPTED, UPDATEKEYS, ROTATE)

# Every state shares one label width, so status and the action commands align.
LABEL_WIDTH = max(len(state.label) for state in
                  (ENCRYPTED, PLAIN, UPDATEKEYS, ROTATE, ERROR, DECRYPTED, UPDATEDKEYS,
                   ROTATED, WOULD_ENCRYPT, WOULD_DECRYPT, WOULD_UPDATEKEYS,
                   WOULD_ROTATE, SKIPPED))


@dataclass(frozen=True)
class Inspection:
    """What one pass of `sops filestatus` (plus metadata) tells us about a file."""

    state: State
    keys: frozenset[Key] | None  # None when the keys cannot be introspected
    error: str | None = None


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


def _iter_rule_keys(fields: Mapping[str, Any]) -> Iterator[tuple[str, str]]:
    """Yield `(backend, raw_value)` for every key a rule references."""
    for backend in BACKENDS:
        for raw in _as_list(fields.get(backend)):
            yield backend, raw
    for group in fields.get("key_groups") or []:
        if isinstance(group, Mapping):
            yield from _iter_rule_keys(group)


def _keys_from_fields(fields: Mapping[str, Any]) -> set[Key]:
    """The master keys a creation rule expects (top-level fields + key_groups)."""
    keys: set[Key] = set()
    for backend, raw in _iter_rule_keys(fields):
        keys.add(Key.of(backend, raw))
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
            keys.add(Key.of(backend, str(value)))
    return keys


def _pronouns(keys: Iterable[Key]) -> dict[Key, str]:
    """Assign unnamed keys a `backend~index` pronoun, numbered per backend."""
    counters: dict[str, int] = {}
    result: dict[Key, str] = {}
    for key in sorted(set(keys)):
        index = counters.get(key.backend, 0)
        counters[key.backend] = index + 1
        result[key] = f"{key.backend}~{index}"
    return result


# --------------------------------------------------------------------------- #
# repository: the parsed .sops.yaml and its creation rules
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

    def sources(self) -> tuple[str, ...]:
        """The key sources the rule configures, for `ls-rules`."""
        found = [backend for backend in BACKENDS if self.fields.get(backend)]
        if self.fields.get("key_groups"):
            found.append("key_groups")
        return tuple(found)

    def keys(self) -> set[Key]:
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

    async def files(self, roots: Sequence[Path] = ()) -> list[tuple[Path, Rule]]:
        """Every `(path, rule)` caught by a rule under *roots* (default: root)."""
        return await asyncio.to_thread(_matched_files, self, tuple(roots))


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


def _rule_key_names(rules: Sequence[Rule], raw_names: Mapping[str, str]) -> dict[Key, str]:
    names: dict[Key, str] = {}
    for rule in rules:
        for backend, raw in _iter_rule_keys(rule.fields):
            name = raw_names.get(raw)
            if name:
                names.setdefault(Key.of(backend, raw), name)
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


# --------------------------------------------------------------------------- #
# the sops driver: the one place that speaks to sops
# --------------------------------------------------------------------------- #
class Sops:
    """A handle on the `sops` binary. Every call goes through here."""

    def __init__(self, binary: str) -> None:
        self.binary = binary

    @classmethod
    def require(cls) -> "Sops":
        binary = shutil.which("sops")
        if binary is None:
            raise ToolError("sops not found in PATH", 127)
        return cls(binary)

    async def _run(
        self, arguments: Sequence[str], env: Mapping[str, str] | None = None
    ) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_child_env(env),
        )
        stdout, stderr = await proc.communicate()
        return (
            proc.returncode,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    async def inspect(self, path: Path) -> Inspection:
        """Ask sops what a file is, and read its master keys if encrypted."""
        code, stdout, stderr = await self._run([self.binary, "filestatus", str(path)])
        if code != 0:
            message = _clean_error(stderr)
            if _is_read_error(message):
                return Inspection(ERROR, None, message)
            # Anything else means "not a sops document": report it as plaintext.
            return Inspection(PLAIN, frozenset())
        try:
            encrypted = bool(json.loads(stdout).get("encrypted"))
        except (ValueError, AttributeError):
            return Inspection(PLAIN, frozenset())
        if not encrypted:
            return Inspection(PLAIN, frozenset())
        keys = await asyncio.to_thread(_actual_keys, path)
        return Inspection(ENCRYPTED, None if keys is None else frozenset(keys))

    async def change(
        self,
        config: Config,
        action: str,
        path: Path,
        env: Mapping[str, str] | None = None,
        in_place: bool = True,
    ) -> str | None:
        """Run a sops write command; return its error message, or None on success.

        `encrypt`/`decrypt` are global flags taking `--in-place`; `updatekeys` is
        a subcommand that always rewrites the file and would otherwise prompt, so
        it gets `--yes` (we do our own confirming).
        """
        if action == "updatekeys":
            arguments = ["updatekeys", "--yes", str(path)]
        else:
            arguments = [f"--{action}"]
            if in_place:
                arguments.append("--in-place")
            arguments.append(str(path))
        command = [self.binary, "--config", str(config.path), *arguments]
        code, _stdout, stderr = await self._run(command, env)
        return None if code == 0 else _clean_error(stderr)


async def inspect_all(sops: Sops, paths: Sequence[Path]) -> list[Inspection]:
    """Inspect many files concurrently, preserving order."""
    limit = asyncio.Semaphore(MAX_CONCURRENCY)

    async def one(path: Path) -> Inspection:
        async with limit:
            return await sops.inspect(path)

    return list(await asyncio.gather(*(one(path) for path in paths)))


def _clean_error(stderr: str) -> str:
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    if not lines:
        return "sops failed"
    match = re.search(r'msg="(.*)"\s*$', lines[-1])
    if not match:
        return lines[-1]
    return match.group(1).replace('\\"', '"').replace("\\n", " ").replace("\\\\", "\\")


def _is_read_error(message: str) -> bool:
    """True when sops failed to *read* the file, rather than to parse it."""
    lowered = message.lower()
    return "error reading file" in lowered or "permission denied" in lowered


# --------------------------------------------------------------------------- #
# age identities we can see (best effort, for naming keys in status -d)
# --------------------------------------------------------------------------- #
AGE_KEY_ENV = "SOPS_AGE_KEY"
AGE_KEY_FILE_ENV = "SOPS_AGE_KEY_FILE"
AGE_KEY_CMD_ENV = "SOPS_AGE_KEY_CMD"


def _child_env(env: Mapping[str, str] | None) -> dict[str, str] | None:
    return {**os.environ, **env} if env else None


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


def _identity_texts(key_files: Sequence[Path], include_env: bool) -> list[str]:
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

    for key_file in key_files:
        read(key_file)
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
    """Run `SOPS_AGE_KEY_CMD` for its identity output; empty on any failure."""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _derive_recipients(texts: Iterable[str]) -> set[str]:
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


async def available_age_keys(
    key_files: Sequence[Path], include_env: bool = False
) -> set[Key]:
    """The age keys we could decrypt with, derived off the event loop."""
    texts = await asyncio.to_thread(_identity_texts, key_files, include_env)
    recipients = await asyncio.to_thread(_derive_recipients, texts)
    return {Key("age", recipient) for recipient in recipients}


# --------------------------------------------------------------------------- #
# paths: how arguments are resolved and how paths are shown
# --------------------------------------------------------------------------- #
def _invocation_dir(args: argparse.Namespace) -> Path:
    """Directory relative paths are interpreted and displayed against."""
    directory = getattr(args, "directory", None)
    return Path(directory).expanduser().resolve() if directory else Path.cwd()


def _resolve(raw: str, args: argparse.Namespace) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = _invocation_dir(args) / path
    return path.resolve()


def _resolve_key_files(args: argparse.Namespace) -> list[Path]:
    key_files = [_resolve(name, args) for name in args.age_key_file]
    for key_file in key_files:
        if not key_file.is_file():
            raise ConfigError(f"age key file not found: {key_file}")
    return key_files


def _display(config: Config, path: Path, args: argparse.Namespace) -> str:
    base = config.root if args.full_name else _invocation_dir(args)
    return Path(os.path.relpath(path, base)).as_posix()


# --------------------------------------------------------------------------- #
# reporting: the one thing that prints
# --------------------------------------------------------------------------- #
class Reporter:
    """Renders states and the `status` report consistently."""

    def __init__(self, color: bool | None = None) -> None:
        self.color = sys.stdout.isatty() if color is None else color

    def paint(self, text: str, color: str | None) -> str:
        if not self.color or color is None:
            return text
        return f"{ANSI[color]}{text}{ANSI['reset']}"

    def outcome(self, state: State, path: str, detail: str | None = None) -> None:
        """One action-command line: `<state>  <path>  [detail]`."""
        label = self.paint(state.label.ljust(LABEL_WIDTH), state.color)
        print(f"{label}  {path}" + (f"  {detail}" if detail else ""))

    def status(
        self,
        rows: Sequence["Row"],
        key_names: Mapping[Key, str],
        available: frozenset[Key] = frozenset(),
        decryptable: frozenset[Path] = frozenset(),
        branch_root: Path | None = None,
    ) -> None:
        all_keys = set(available)
        for row in rows:
            all_keys |= row.expected
            if row.keys is not None:
                all_keys |= row.keys
        labels = _labels(all_keys, key_names)

        # A legend of every key in play; the ones we can decrypt with go orange.
        if labels:
            for key in sorted(all_keys, key=lambda k: labels[k]):
                shade = "orange" if key in available else None
                print(self.paint(f"{labels[key]}: {key.text}", shade))
            print()

        if branch_root is not None:
            print(f"## {branch_root}")

        # For each row: the key-diff tokens, the keys we can name that open it,
        # and whether sops opened it through some other (unnameable) source.
        entries = [
            (
                _key_diff(row, labels),
                _open_keys(row, labels, available, decryptable),
            )
            for row in rows
        ]
        plain_keys = [" ".join(text for text, _shade in diff) for diff, _ in entries]
        plain_marks = [
            " ".join(f"*{name}" for name in names) if names else ("*" if opened else "")
            for _diff, (names, opened) in entries
        ]

        width_path = max((len(row.path) for row in rows), default=0)
        width_keys = max((len(text) for text in plain_keys if text != "-"), default=0)
        width_marks = max((len(text) for text in plain_marks), default=0)

        for row, (diff, (names, _opened)), keys_text, plain_mark in zip(
            rows, entries, plain_keys, plain_marks
        ):
            label = self.paint(row.state.label.ljust(LABEL_WIDTH), row.state.color)
            line = f"{label}  {row.path.ljust(width_path)}"
            if width_keys:
                colored = " ".join(
                    self.paint(text, shade) if shade else text for text, shade in diff
                )
                line += f"  {colored}{' ' * (width_keys - len(keys_text))}"
            if width_marks:
                if names:
                    mark = " ".join(self.paint(f"*{name}", "orange") for name in names)
                elif plain_mark:
                    mark = self.paint("*", "orange")
                else:
                    mark = ""
                line += f"  {mark}{' ' * (width_marks - len(plain_mark))}"
            line = line.rstrip()
            if row.error is not None:
                line += f"  {row.error}"
            print(line)


def _labels(keys: Iterable[Key], key_names: Mapping[Key, str]) -> dict[Key, str]:
    pronouns = _pronouns(keys)
    return {key: key_names.get(key) or pronouns[key] for key in pronouns}


def _key_diff(row: "Row", labels: Mapping[Key, str]) -> list[tuple[str, str | None]]:
    """The file's keys vs the rule's: white same, green `+` missing, red `-` extra."""
    if row.keys is None:
        return [("?", None)]
    keys, expected = row.keys, row.expected
    tokens: list[tuple[str, str | None]] = []
    for key in sorted(keys | expected, key=lambda key: labels[key]):
        label = labels[key]
        if key in keys and key in expected:
            tokens.append((label, None))  # matches .sops.yaml -> white
        elif key in expected:
            tokens.append((f"+{label}", "green"))  # rule has it, file lacks it
        else:
            tokens.append((f"-{label}", "red"))  # file has it, rule lacks it
    return tokens or [("-", None)]


def _open_keys(
    row: "Row",
    labels: Mapping[Key, str],
    available: frozenset[Key],
    decryptable: frozenset[Path],
) -> tuple[tuple[str, ...], bool]:
    """The named keys that open this file, plus whether sops opened it at all."""
    names = tuple(
        labels[key]
        for key in sorted(row.keys or (), key=lambda key: labels[key])
        if key in available
    )
    return names, row.source in decryptable


@dataclass(frozen=True)
class Row:
    """One line of the status report: a file, its state, and its key diff."""

    source: Path
    path: str
    state: State
    expected: frozenset[Key]
    keys: frozenset[Key] | None  # None = unknown
    error: str | None = None


def _drift_state(inspection: Inspection, expected: frozenset[Key]) -> State:
    """The file's state once its keys are compared with the rule's.

    `sops filestatus` alone only knows encrypted / not / error; `need updatekeys`
    and `need rotate` come from diffing the file's actual keys against the rule's.
    """
    if inspection.state is ERROR:
        return ERROR
    if inspection.state is PLAIN:
        return PLAIN  # not a sops document: it carries none of the rule's keys
    if inspection.keys is None:
        return ENCRYPTED  # encrypted, but its keys cannot be introspected
    if inspection.keys - expected:
        return ROTATE  # file has a key the rule lacks -> a red `-`
    if expected - inspection.keys:
        return UPDATEKEYS  # rule wants a key the file lacks -> a green `+`
    return ENCRYPTED


def _status_row(config: Config, path: Path, rule: Rule, inspection: Inspection,
                args: argparse.Namespace) -> Row:
    expected = frozenset(rule.keys())
    display = _display(config, path, args)
    state = _drift_state(inspection, expected)
    if state is ERROR:
        return Row(path, display, ERROR, expected, None, inspection.error)
    keys = None if state is ENCRYPTED and inspection.keys is None else inspection.keys
    if state is PLAIN:
        keys = frozenset()
    return Row(path, display, state, expected, keys)


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


def _add_paths(parser: argparse.ArgumentParser, help: str) -> None:
    """Add the common trailing PATH argument (usable after `--`, like git)."""
    parser.add_argument("paths", nargs="*", metavar="PATH", help=help)


def _add_full_name(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--full-name",
        action="store_true",
        help="show paths relative to the repository root",
    )


def _add_age_key_file(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument(
        "--age-key-file",
        action="append",
        default=[],
        metavar="FILE",
        help=help,
    )


class FileCommand(Subcommand):
    """A command that walks the files caught by a creation rule."""

    paths_help = "limit these paths"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        _add_paths(parser, self.paths_help)
        _add_full_name(parser)

    def roots(self, args: argparse.Namespace) -> list[Path]:
        return [_resolve(raw, args) for raw in args.paths]


class ActionCommand(FileCommand):
    """A command that inspects each matched file and may change it in place.

    The `encrypt`/`decrypt`/`updatekeys` loop lives here once: inspect, classify
    (against the rule's keys, so `need updatekeys` and `need rotate` are just
    states), then skip, report, ask, or mutate. Subclasses only say which states
    they act on and how.

    `probe_dry_run` says whether `--dry-run` should *ask sops* (read-only) — true
    for `decrypt`, where only sops can say whether a key is at hand — or merely
    predict (false for `encrypt`/`updatekeys`, whose drift we already know).
    """

    verb: str
    would: State
    done: State
    probe_dry_run = False
    nothing: str | None = None  # message when nothing matched; defaults to verb

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        parser.add_argument(
            "-n", "--dry-run", action="store_true",
            help="only show what would change",
        )
        parser.add_argument(
            "-i", "--interactive", action="store_true",
            help="confirm each file before changing it",
        )

    def target_states(self, args: argparse.Namespace) -> Collection[State]:
        """The states this command acts on, given its options."""
        raise NotImplementedError

    def identity_environment(
        self, args: argparse.Namespace
    ) -> tuple[dict[str, str] | None, Path | None]:
        """Extra environment (and a temp file to clean up) for the sops call."""
        return None, None

    async def mutate(
        self,
        sops: Sops,
        config: Config,
        path: Path,
        env: Mapping[str, str] | None,
        in_place: bool,
    ) -> str | None:
        """Perform the change; return an error message, or None on success."""
        raise NotImplementedError

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = Sops.require()
        env, temporary = self.identity_environment(args)
        targets = self.target_states(args)
        reporter = Reporter()
        acted = errors = 0
        try:
            for path, rule in await config.files(self.roots(args)):
                display = _display(config, path, args)
                inspection = await sops.inspect(path)

                if inspection.state is ERROR:
                    reporter.outcome(ERROR, display, inspection.error)
                    errors += 1
                    continue
                state = _drift_state(inspection, frozenset(rule.keys()))
                if state not in targets:
                    continue
                if args.dry_run and not self.probe_dry_run:
                    reporter.outcome(self.would, display)
                    acted += 1
                    continue
                if not args.dry_run and args.interactive and not await _confirm(
                    self.verb, display
                ):
                    reporter.outcome(SKIPPED, display)
                    continue

                # On a probing dry-run this is a read-only call; otherwise it
                # really changes the file.
                failure = await self.mutate(
                    sops, config, path, env, in_place=not args.dry_run
                )
                if failure is None:
                    reporter.outcome(self.would if args.dry_run else self.done, display)
                    acted += 1
                else:
                    reporter.outcome(ERROR, display, failure)
                    errors += 1

            if not acted and not errors:
                print(self.nothing or f"nothing to {self.verb}")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return 1 if errors else 0


async def _confirm(verb: str, display: str) -> bool:
    answer = await asyncio.to_thread(input, f"{verb} {display}? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


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
            backends = ",".join(rule.sources()) or "-"
            print(f"{rule.name}\t{rule.path_regex or '*'}\t{backends}")
        return 0


@subcommand
class LsFilesCommand(FileCommand):
    name = "ls-files"
    help = "list files caught by a creation rule"
    paths_help = "limit the listing to these paths"

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        for path, _rule in await config.files(self.roots(args)):
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
class StatusCommand(FileCommand):
    name = "status"
    help = "report whether matched files are encrypted"
    paths_help = "limit the report to these paths"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        parser.add_argument(
            "--branch", "-b", action="store_true", help="show the repository header"
        )
        parser.add_argument(
            "--porcelain", action="store_true",
            help="machine-readable output: '<code>\\t<path>'",
        )
        parser.add_argument(
            "--decrypt-check", "-d", action="store_true",
            help="try to decrypt each file and mark the ones that open",
        )
        _add_age_key_file(
            parser, "age identity file to check against (with --decrypt-check/-d; repeatable)"
        )

    async def run(self, config: Config, args: argparse.Namespace) -> int:
        sops = Sops.require()
        key_files = _resolve_key_files(args)
        matches = await config.files(self.roots(args))
        inspections = await inspect_all(sops, [path for path, _rule in matches])
        rows = [
            _status_row(config, path, rule, inspection, args)
            for (path, rule), inspection in zip(matches, inspections)
        ]

        if args.porcelain:
            for row in rows:
                print(f"{row.state.code}\t{row.path}")
            return 0

        available: frozenset[Key] = frozenset()
        decryptable: frozenset[Path] = frozenset()
        if args.decrypt_check:
            available = frozenset(await available_age_keys(key_files, include_env=True))
            decryptable = await _probe_decryptable(sops, config, rows, key_files)

        Reporter().status(
            rows,
            config.key_names,
            available,
            decryptable,
            config.root if args.branch else None,
        )
        return 0


async def _probe_decryptable(
    sops: Sops, config: Config, rows: Sequence[Row], key_files: Sequence[Path]
) -> frozenset[Path]:
    """Ask sops to open every encrypted file; collect the ones it can.

    Naming is best-effort (see `available_age_keys`); a key can also reach sops
    through sources we cannot enumerate — an SSH key, a key service, … — so the
    only honest test of "does this open?" is to ask sops.
    """
    targeted = [row for row in rows if row.state in ENCRYPTED_STATES]
    env, temporary = _age_key_env(key_files)
    limit = asyncio.Semaphore(MAX_CONCURRENCY)

    async def check(row: Row) -> Path | None:
        async with limit:
            failure = await sops.change(config, "decrypt", row.source, env, in_place=False)
        return row.source if failure is None else None

    try:
        results = await asyncio.gather(*(check(row) for row in targeted))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return frozenset(path for path in results if path is not None)


@subcommand
class EncryptCommand(ActionCommand):
    name = "encrypt"
    help = "encrypt, in place, every matched file that is not encrypted yet"

    verb = "encrypt"
    would = WOULD_ENCRYPT
    done = ENCRYPTED

    def target_states(self, args: argparse.Namespace) -> Collection[State]:
        return {PLAIN}

    async def mutate(
        self,
        sops: Sops,
        config: Config,
        path: Path,
        env: Mapping[str, str] | None,
        in_place: bool,
    ) -> str | None:
        return await sops.change(config, "encrypt", path)


class AgeKeyAction(ActionCommand):
    """An action whose sops command needs an age identity to unlock a data key.

    `decrypt`, `updatekeys` and `rotate` all take `--age-key-file`, hand the
    identity to sops through `SOPS_AGE_KEY_FILE`, and run one sops command. They
    differ only in *which* command and *which* states they act on, so the shared
    plumbing lives here.
    """

    sops_action: str
    key_file_help = "age identity file (repeatable)"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        _add_age_key_file(parser, self.key_file_help)

    def identity_environment(
        self, args: argparse.Namespace
    ) -> tuple[dict[str, str] | None, Path | None]:
        return _age_key_env(_resolve_key_files(args))

    async def mutate(
        self,
        sops: Sops,
        config: Config,
        path: Path,
        env: Mapping[str, str] | None,
        in_place: bool,
    ) -> str | None:
        return await sops.change(config, self.sops_action, path, env, in_place=in_place)


@subcommand
class DecryptCommand(AgeKeyAction):
    name = "decrypt"
    help = "decrypt, in place, every matched file that is encrypted (a thin sops wrapper)"

    verb = "decrypt"
    would = WOULD_DECRYPT
    done = DECRYPTED
    probe_dry_run = True  # only sops can say whether a key is at hand
    sops_action = "decrypt"

    def target_states(self, args: argparse.Namespace) -> Collection[State]:
        # Any encrypted file: decryption does not care about key drift.
        return set(ENCRYPTED_STATES)


@subcommand
class UpdatekeysCommand(AgeKeyAction):
    name = "updatekeys"
    help = "reconcile matched files' keys with .sops.yaml (adds and removes)"

    verb = "updatekeys"
    would = WOULD_UPDATEKEYS
    done = UPDATEDKEYS
    nothing = "nothing to update"
    sops_action = "updatekeys"

    def configure(self, parser: argparse.ArgumentParser) -> None:
        super().configure(parser)
        parser.add_argument(
            "--rotate", action="store_true",
            help="also update files that carry a key .sops.yaml no longer lists",
        )

    def target_states(self, args: argparse.Namespace) -> Collection[State]:
        states = {UPDATEKEYS}
        if args.rotate:
            states.add(ROTATE)  # `sops updatekeys` drops the stale keys too
        return states


@subcommand
class RotateCommand(AgeKeyAction):
    name = "rotate"
    help = "re-key matched files: sync their keys and generate a new data key"

    verb = "rotate"
    would = WOULD_ROTATE
    done = ROTATED
    nothing = "nothing to rotate"
    sops_action = "rotate"

    def target_states(self, args: argparse.Namespace) -> Collection[State]:
        return {ROTATE}

    async def mutate(
        self,
        sops: Sops,
        config: Config,
        path: Path,
        env: Mapping[str, str] | None,
        in_place: bool,
    ) -> str | None:
        # `sops rotate` re-encrypts with the file's *existing* master keys, so on
        # its own it would leave the `need rotate` drift in place. Rotating first
        # (while the old key can still unlock the data key), then syncing keys,
        # both re-keys and drops the stale ones — even when the stale key is the
        # only one we hold.
        failure = await sops.change(config, "rotate", path, env, in_place=in_place)
        if failure is not None:
            return failure
        return await sops.change(config, "updatekeys", path, env)


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
    except ToolError as exc:
        print(f"sops-tool: {exc}", file=sys.stderr)
        return exc.code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
