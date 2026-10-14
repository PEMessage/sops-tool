# sops-tool

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
| porcelain | `encrypt`  | encrypt matched files that are not encrypted yet    |
| porcelain | `decrypt`  | decrypt matched files that are encrypted            |

## Usage

`status` mirrors `git status --short [--branch]`: one line per matched file,
with a coloured state word, and paths relative to the current directory. Each
line also names the master key(s), compared against the keys the matching rule
expects.

A key can be given a human name in `.sops.yaml` — through a top-level `keys:`
map (which sops ignores) or a YAML anchor — and referenced by alias. A rule can
also just inline the bare recipient, in which case the key has no name:

```yaml
keys:
  admin: &admin age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
creation_rules:
  - path_regex: ^secrets/
    age: *admin
  - path_regex: \.yaml$
    age: age1azjar2evsuakyv9cjg66vhzvy3uwkw7uvu54fm9ewp9e4petdpkqzzpqrh
```

`status` labels a named key by that name; a key without one gets a short
**pronoun** of the form `<backend>~<index>`. Either way the keys in play are
defined at the top of the output. The keys are then shown like a diff against
`.sops.yaml`: white means the key matches, a green `+` is a key `.sops.yaml` has
but the file lacks, and a red `-` is a key the file has but `.sops.yaml` does
not:

```console
$ sops-tool status --branch
admin:  age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
age~0:  age1azjar2evsuakyv9cjg66vhzvy3uwkw7uvu54fm9ewp9e4petdpkqzzpqrh
backup: age1ck8af8dr5yq3j8sea5jxg58vvjmth6m80gq5tf2n09ztfqfrxd0stl8awd

## /repo
encrypted        config/db.yaml            age~0
encrypted        secrets/dev.yaml          admin backup
encrypted        kek/data.txt              admin backup
not encrypted    secrets/extra.yaml        +admin +backup
need updatekeys  secrets/missing-key.yaml  admin +backup
need rotate      app/extra-key.yaml        -admin +age~0 -backup
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
$ sops-tool status -- secrets config
encrypted        secrets/dev.yaml          admin backup
not encrypted    secrets/extra.yaml        +admin +backup
need updatekeys  secrets/missing-key.yaml  +backup admin
```

Machine-readable output mirrors `git status --porcelain`: one `<code>\t<path>`
line per file, with `E` (encrypted), `U` (not encrypted), `+` (need updatekeys),
`-` (need rotate) or `!` (error):

```console
$ sops-tool status --porcelain
!	data/broken.yaml
E	config/db.yaml
U	data/blob.bin
-	app/extra-key.yaml
+	secrets/missing-key.yaml
```

`encrypt` is the write-side counterpart: it encrypts, in place, every matched
file that is not encrypted yet, leaving already-encrypted files alone. It takes
the same `--` path filter, and `-n/--dry-run` prints what it would do without
touching anything:

```console
$ sops-tool encrypt --dry-run -- secrets
would encrypt  secrets/extra.yaml

$ sops-tool encrypt -- secrets
encrypted      secrets/extra.yaml
```

Use `-i/--interactive` to confirm each file one at a time:

```console
$ sops-tool encrypt -i
encrypt secrets/extra.yaml? [y/N] y
encrypted      secrets/extra.yaml
```

`decrypt` is the mirror image: it decrypts, in place, every matched file that is
encrypted. It needs a private key, which sops finds the usual way
(`SOPS_AGE_KEY_FILE` and friends):

```console
$ SOPS_AGE_KEY_FILE=keys/age.txt sops-tool decrypt -- secrets
decrypted      secrets/dev.yaml
decrypted      secrets/missing-key.yaml
decrypted      secrets/prod.yaml
```

It takes the same `--` path filter and `-n/--dry-run` / `-i/--interactive`
flags.

Plumbing is stable and script-friendly:

```console
$ sops-tool root
/repo

$ sops-tool ls-rules
#0	^secrets/.*\.yaml$	age
#1	.*\.yaml$	pgp,kms

$ sops-tool match secrets/prod.yaml
#0
```

`status` calls `sops filestatus` for each matched file. A file sops cannot parse
is treated as `not encrypted`; only a file it cannot *read* shows up as `error`.

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
that is `need rotate`, plaintext files still caught by a rule, a binary and a
key file that sops cannot parse (both reported as `not encrypted`), a file
matched by no rule, and an unreadable symlink that shows up as `error`. It also
shows first-match win ordering between a specific `^secrets/prod\.yaml$` rule
and broader ones.

Two folders make the key story concrete:

- `keys/` holds the real age master keys that sops uses to unlock a file's data
  key. They are regenerated on every `make reset`, and are deliberately **not**
  covered by any creation rule — they are the keys, not encrypted data.
- `kek/` holds a *key-encryption-key*, but only as ordinary **data**: a `.txt`
  that is itself encrypted by one of the keys (`kek/data.txt`), so `status`
  lists it like any other encrypted file.

`make encrypt` encrypts the sandbox's still-plaintext files in place, and
`make decrypt` reverses it (using `keys/`); the `dry-run` variants only print
what would happen. `keys/` is untouched by both, because no rule covers it.

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
