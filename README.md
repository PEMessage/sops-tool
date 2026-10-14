# easy-sops

A tiny, git-style front-end for [sops](https://github.com/getsops/sops),
packaged as one executable script using an inline [uv](https://docs.astral.sh/uv/)
toolchain. No repo, no virtualenv, no install step beyond `uv`.

## Design

Every command runs against a **repository**: the nearest `.sops.yaml` found by
walking up from the current directory. `-C DIR` starts that search — and
resolves relative path arguments — in `DIR`, exactly like `git -C`.

The config is loaded once into an in-memory `Config` object; commands are thin,
`async` queries over it. Blocking work (directory walks, YAML parsing) runs on
threads via `asyncio.to_thread`, and `sops` is driven as a real async subprocess
— so `status` fans its `sops filestatus` calls out concurrently.

Commands follow git's porcelain/plumbing split:

| kind      | command    | what it does                                      |
| --------- | ---------- | ------------------------------------------------- |
| plumbing  | `root`     | print the repository root                          |
| plumbing  | `ls-rules` | list creation rules (`name`, `path_regex`, backends) |
| plumbing  | `ls-files` | list files caught by a rule                        |
| plumbing  | `match`    | print the rule for a path (exit 1 if none)         |
| porcelain | `status`   | report whether matched files are encrypted         |

## Usage

```console
$ easy-sops status
Encrypted:
  plain.yaml

Not encrypted:
  secrets/dev.yaml
  secrets/prod.yaml
```

Machine-readable output mirrors `git status --porcelain`: one `<code>\t<path>`
line per file, with `E` (encrypted), `U` (unencrypted) or `!` (error):

```console
$ easy-sops status --porcelain
!	bin.dat
E	plain.yaml
U	secrets/dev.yaml
U	secrets/prod.yaml
```

Plumbing is stable and script-friendly:

```console
$ easy-sops root
/repo

$ easy-sops ls-rules
#0	^secrets/.*\.yaml$	age
#1	.*\.yaml$	pgp,kms

$ easy-sops match secrets/prod.yaml
#0
```

`status` calls `sops filestatus` for each matched file; a file sops cannot
classify is reported as an error.

## Matching semantics

Identical to sops' own behaviour:

- the config file must be named `.sops.yaml`;
- `path_regex` is matched, unanchored, against the file path **relative to the
  repo root** (a search, not a full match);
- the **first** matching creation rule wins;
- a rule without a `path_regex` matches every file.

Patterns are compiled with Python's `re`; for typical path patterns this is
compatible with sops' Go/RE2 engine. Common VCS/venv directories (`.git`,
`.venv`, `node_modules`, …) are skipped during the walk, and `.sops.yaml` itself
is never reported.

## Exit codes

`0` on success, `1` when `match` finds no rule, `2` for a missing/invalid
repository, `127` if `sops` is not found in `PATH`.
