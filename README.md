# easy-sops

A tiny, git-style front-end for [sops](https://github.com/getsops/sops),
packaged as one executable script using an inline [uv](https://docs.astral.sh/uv/)
toolchain. No repo, no virtualenv, no install step beyond `uv`.

## Design

Every command runs against a **repository**: the nearest `.sops.yaml` found by
walking up from the current directory. `-C DIR` starts that search — and
resolves relative path arguments — in `DIR`, exactly like `git -C`.

The config is loaded once into an in-memory `Config` object. Each command is a
self-contained `Subcommand` class: it defines its own arguments and its own
`run`, and registers itself with the `@subcommand` decorator — there is no
central command table and no single place that knows every flag. Blocking work
(directory walks, YAML parsing) runs on threads via `asyncio.to_thread`, and
`sops` is driven as a real async subprocess, so `status` fans its
`sops filestatus` calls out concurrently.

Commands follow git's porcelain/plumbing split:

| kind      | command    | what it does                                      |
| --------- | ---------- | ------------------------------------------------- |
| plumbing  | `root`     | print the repository root                          |
| plumbing  | `ls-rules` | list creation rules (`name`, `path_regex`, backends) |
| plumbing  | `ls-files` | list files caught by a rule                        |
| plumbing  | `match`    | print the rule for a path (exit 1 if none)         |
| porcelain | `status`   | report whether matched files are encrypted         |

## Usage

`status` mirrors `git status --short [--branch]`: one line per matched file,
with a coloured state word, and paths relative to the current directory. Each
line also names the master key(s), compared against the keys the matching rule
expects.

A key can be given a human name in `.sops.yaml`, either through a top-level
`keys:` map (which sops ignores) or a YAML anchor, and referenced by alias:

```yaml
keys:
  admin: &admin age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
creation_rules:
  - path_regex: ^secrets/
    age: *admin
```

`status` labels a named key by that name; a key without one gets a short
**pronoun** of the form `<backend>~<index>`. Either way the keys in play are
defined at the top of the output. The keys are then shown like a diff against
`.sops.yaml`: white means the key matches, a green `+` is a key `.sops.yaml` has
but the file lacks, and a red `-` is a key the file has but `.sops.yaml` does
not:

```console
$ easy-sops status --branch
admin:  age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
backup: age1ck8af8dr5yq3j8sea5jxg58vvjmth6m80gq5tf2n09ztfqfrxd0stl8awd

## /repo
encrypted        config/db.yaml            admin
encrypted        secrets/dev.yaml          admin backup
not encrypted    secrets/extra.yaml        +admin +backup
not encrypted    kek/age.txt               +admin +backup
need updatekeys  secrets/missing-key.yaml  +backup admin
need rotate      app/extra-key.yaml        -backup admin
error            data/broken.yaml          ?  <sops filestatus message>
```

The state words are named after the sops command that would fix the file:

- **encrypted** (green) — no drift: the file's keys match the rule's;
- **not encrypted** (white) — the rule covers the file, but it is plaintext (or
  sops cannot parse it as a sops document at all);
- **need updatekeys** (yellow) — `+` drift: the rule wants a key the file lacks
  (`sops updatekeys` adds it);
- **need rotate** (yellow) — `-` drift: the file carries a key the rule does not
  list (`sops rotate`);
- **error** (red) — `sops filestatus` could not *read* the file (a broken
  symlink, a permission problem, …); the message is appended to that file's own
  line, so it never disturbs the others.

Add `--branch` for the `##` header. Paths are printed relative to the current
directory by default; pass `--full-name` for repository-root-relative paths.
Like git, a `--` separates options from paths, which limits the report to those
paths:

```console
$ easy-sops status -- secrets config
encrypted        secrets/dev.yaml          admin backup
not encrypted    secrets/extra.yaml        +admin +backup
need updatekeys  secrets/missing-key.yaml  +backup admin
```

Machine-readable output mirrors `git status --porcelain`: one `<code>\t<path>`
line per file, with `E` (encrypted), `U` (not encrypted), `+` (need updatekeys),
`-` (need rotate) or `!` (error):

```console
$ easy-sops status --porcelain
!	data/blob.bin
E	config/db.yaml
+	secrets/missing-key.yaml
-	app/extra-key.yaml
U	secrets/extra.yaml
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

## Playground

The `Makefile` builds a throwaway sandbox under `./playground/` (gitignored) so
you can try every command without touching real secrets. It needs `sops` and
`age-keygen`.

```console
$ make help         # list the playground targets
$ make playground   # create ./playground/ with sample rules and secrets
$ make demo         # run every command against it
$ make clean        # delete it
```

The sandbox contains several kinds of files on purpose: correctly encrypted
ones (including one with two keys), a file that is `need updatekeys`, a file
that is `need rotate`, plaintext files still caught by a rule, a key file and a
binary that sops cannot parse (both reported as `not encrypted`), a file matched
by no rule, and an unreadable symlink that shows up as `error`. It also shows
first-match win ordering between a specific `^secrets/prod\.yaml$` rule and
broader ones.

The age master keys — the KEKs (key encryption keys) that sops unlocks a file's
data key with — live in `kek/`. They are regenerated on every `make reset` and
are listed by `status` through their own `^kek/` rule (as plaintext; a KEK is
never encrypted with itself).

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
