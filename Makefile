# sops-tool playground
#
# `make playground` builds a throwaway sandbox under ./playground/ (kept out of
# git) so you can try every command without touching real secrets.
#
#   make playground   build the sandbox
#   make demo         build it, then walk through the commands
#   make clean        delete the sandbox
#
# Requires: sops, age-keygen.
#
# Note: `.ONESHELL` strips leading whitespace from every recipe line, so file
# contents are written with `printf` and indentation kept inside quotes.

PLAYGROUND := playground
STAMP      := $(PLAYGROUND)/.ready
SOPS_TOOL  ?= $(CURDIR)/sops-tool.py
SOPS       ?= sops
AGE_KEYGEN ?= age-keygen

# Path passed to `make match`, e.g. `make match FILE=secrets/dev.yaml`.
FILE ?= secrets/prod.yaml

SHELL       := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

.PHONY: help playground demo status porcelain ls-rules ls-files match encrypt dry-run decrypt decrypt-dry-run clean reset

help:
	@printf '%s\n' '' 'sops-tool playground' '' '  make playground    build ./$(PLAYGROUND)/ with sample rules and secrets' '  make demo          build it, then run every command against it' '  make status        sops-tool -C $(PLAYGROUND) status' '  make porcelain     sops-tool -C $(PLAYGROUND) status --porcelain' '  make ls-rules      list the sample creation rules' '  make ls-files      list files caught by the rules' '  make match         rule for FILE (default: $(FILE))' '  make encrypt       encrypt the not-yet-encrypted files in place' '  make decrypt       decrypt the encrypted files in place (uses keys/)' '  make dry-run       encrypt --dry-run: only print what would change' '  make decrypt-dry-run  decrypt --dry-run' '  make clean         remove ./$(PLAYGROUND)/' '  make reset         clean, then rebuild' ''

$(STAMP): $(SOPS_TOOL) $(MAKEFILE_LIST)
	@rm -rf $(PLAYGROUND)
	mkdir -p $(PLAYGROUND)/secrets $(PLAYGROUND)/config $(PLAYGROUND)/app $(PLAYGROUND)/deploy/prod $(PLAYGROUND)/keys $(PLAYGROUND)/kek $(PLAYGROUND)/data

	$(AGE_KEYGEN) -o $(PLAYGROUND)/keys/age.txt >/dev/null
	$(AGE_KEYGEN) -o $(PLAYGROUND)/keys/age2.txt >/dev/null
	$(AGE_KEYGEN) -o $(PLAYGROUND)/keys/age3.txt >/dev/null
	recipient=$$($(AGE_KEYGEN) -y $(PLAYGROUND)/keys/age.txt)
	recipient2=$$($(AGE_KEYGEN) -y $(PLAYGROUND)/keys/age2.txt)
	recipient3=$$($(AGE_KEYGEN) -y $(PLAYGROUND)/keys/age3.txt)

	printf '%s\n' \
		'# Sample config. Rules are tried in order; the first match wins.' \
		'# Two ways to give a key to a rule:' \
		'#   - named up top: `keys:` + &anchor, referenced as *alias;' \
		'#   - inline: a bare recipient literal, which has no name, so sops-tool' \
		'#     shows it with a generated `backend~index` pronoun instead.' \
		'keys:' \
		'  admin: &admin __RECIPIENT__' \
		'  backup: &backup __RECIPIENT2__' \
		'' \
		'creation_rules:' \
		'  - path_regex: ^secrets/prod\.yaml$$' \
		'    age: *admin' \
		'  - path_regex: ^secrets/' \
		'    age:' \
		'      - *admin' \
		'      - *backup' \
		'  - path_regex: \.yaml$$' \
		'    age: __RECIPIENT3__' \
		'  - path_regex: ^data/' \
		'    age: *admin' \
		'  - path_regex: ^kek/' \
		'    age:' \
		'      - *admin' \
		'      - *backup' \
		> $(PLAYGROUND)/.sops.yaml
	sed -i -e "s|__RECIPIENT3__|$$recipient3|g" -e "s|__RECIPIENT2__|$$recipient2|g" -e "s|__RECIPIENT__|$$recipient|g" $(PLAYGROUND)/.sops.yaml

	printf '%s\n' \
		'database:' \
		'  host: db.prod.internal' \
		'  password: hunter2' \
		'api_key: sk-prod-abc123' \
		> $(PLAYGROUND)/secrets/prod.yaml
	printf '%s\n' \
		'database:' \
		'  host: db.dev.internal' \
		'  password: hunter2' \
		'api_key: sk-dev-xyz789' \
		> $(PLAYGROUND)/secrets/dev.yaml
	printf '%s\n' \
		'user: reporting' \
		'password: supersecret' \
		> $(PLAYGROUND)/config/db.yaml

	printf '%s\n' \
		'# matched by the secrets rule, but deliberately left unencrypted' \
		'note: forgotten to encrypt' \
		> $(PLAYGROUND)/secrets/extra.yaml
	printf '%s\n' \
		'# matched by the secrets rule (which expects two keys) but encrypted' \
		'# to one, so a key the rule wants is missing -> plus-sign drift ->' \
		'# `status` says need updatekeys' \
		'scope: missing-key-demo' \
		> $(PLAYGROUND)/secrets/missing-key.yaml
	printf '%s\n' \
		'# matched by the catch-all rule (which expects one key) but encrypted' \
		'# to an extra key, so the file has a key the rule lacks -> minus-sign' \
		'# drift -> `status` says need rotate' \
		'scope: extra-key-demo' \
		> $(PLAYGROUND)/app/extra-key.yaml
	printf '%s\n' \
		'# matched by the dot-yaml catch-all rule, left unencrypted' \
		'debug: false' \
		> $(PLAYGROUND)/app/settings.yaml
	printf '%s\n' \
		'# nested YAML, also caught by the catch-all rule, left unencrypted' \
		'replicas: 3' \
		> $(PLAYGROUND)/deploy/prod/values.yaml
	printf '%s\n' \
		'not matched by any rule, so sops-tool never lists this file' \
		> $(PLAYGROUND)/notes.txt
	# `kek/` is just special *data*: a .txt encrypted by a key. The real sops
	# keys live in keys/ and are deliberately not covered by any rule.
	printf '%s\n' \
		'# key-encryption-key material, stored encrypted at rest' \
		'kek: 8f4c1d9a2b7e6053' \
		> $(PLAYGROUND)/kek/data.txt

	head -c 64 /dev/urandom > $(PLAYGROUND)/data/blob.bin
	# A broken symlink: sops cannot read it, so `status` reports `error`.
	ln -sf missing-target $(PLAYGROUND)/data/broken.yaml

	# sops looks for .sops.yaml relative to the cwd, so point it at the sandbox.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/secrets/prod.yaml
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/secrets/dev.yaml
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/config/db.yaml
	# The rule wants a key the file lacks -> plus-sign drift -> `need updatekeys`.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --age "$$recipient" --encrypt --in-place $(PLAYGROUND)/secrets/missing-key.yaml
	# The file has a key the rule lacks -> minus-sign drift -> `need rotate`.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --age "$$recipient,$$recipient2" --encrypt --in-place $(PLAYGROUND)/app/extra-key.yaml
	# The KEK is data, so the ^kek/ rule encrypts it (a .txt becomes JSON).
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/kek/data.txt

	touch $(STAMP)
	printf '%s\n' '' 'playground ready in ./$(PLAYGROUND)/' '  named keys:      admin, backup (from .sops.yaml anchors)' '  inline key:      one rule uses a bare recipient -> shown as a pronoun' '  encrypted:       secrets/prod.yaml, config/db.yaml, kek/data.txt' '  multi-key:       secrets/dev.yaml (two keys)' '  need updatekeys: secrets/missing-key.yaml (missing an expected key)' '  need rotate:     app/extra-key.yaml (has an extra key)' '  not encrypted:   secrets/extra.yaml, app/settings.yaml, deploy/prod/values.yaml, data/blob.bin' '  sops keys:       keys/age*.txt (the real keys; not rule-covered, not listed)' '  kek (data):      kek/data.txt (a txt encrypted by one of those keys)' '  not matched:     notes.txt' '  error:           data/broken.yaml (unreadable symlink)' '' 'try: make demo'

playground: $(STAMP)

demo: $(STAMP)
	@printf '\n=== root ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) root
	printf '\n=== ls-rules ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) ls-rules
	printf '\n=== ls-files ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) ls-files
	printf '\n=== match secrets/dev.yaml ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) match secrets/dev.yaml
	printf '\n=== match notes.txt (unmatched, exits 1) ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) match notes.txt || true
	printf '\n=== status --branch ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) status --branch
	printf '\n=== status --porcelain ===\n'
	$(SOPS_TOOL) -C $(PLAYGROUND) status --porcelain

status: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) status

porcelain: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) status --porcelain

ls-rules: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) ls-rules

ls-files: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) ls-files

match: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) match $(FILE)

encrypt: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) encrypt || true

dry-run: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) encrypt --dry-run || true

decrypt: $(STAMP)
	@cat $(PLAYGROUND)/keys/age*.txt > $(PLAYGROUND)/.agekeys
	@SOPS_AGE_KEY_FILE=$(CURDIR)/$(PLAYGROUND)/.agekeys $(SOPS_TOOL) -C $(PLAYGROUND) decrypt || true

decrypt-dry-run: $(STAMP)
	@$(SOPS_TOOL) -C $(PLAYGROUND) decrypt --dry-run || true

clean:
	@rm -rf $(PLAYGROUND)

reset: clean playground
