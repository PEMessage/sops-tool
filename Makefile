# easy-sops playground
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
EASY_SOPS  ?= $(CURDIR)/easy-sops.py
SOPS       ?= sops
AGE_KEYGEN ?= age-keygen

# Path passed to `make match`, e.g. `make match FILE=secrets/dev.yaml`.
FILE ?= secrets/prod.yaml

SHELL       := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

.PHONY: help playground demo status porcelain ls-rules ls-files match clean reset

help:
	@printf '%s\n' '' 'easy-sops playground' '' '  make playground   build ./$(PLAYGROUND)/ with sample rules and secrets' '  make demo         build it, then run every command against it' '  make status       easy-sops -C $(PLAYGROUND) status' '  make porcelain    easy-sops -C $(PLAYGROUND) status --porcelain' '  make ls-rules     list the sample creation rules' '  make ls-files     list files caught by the rules' '  make match        rule for FILE (default: $(FILE))' '  make clean        remove ./$(PLAYGROUND)/' '  make reset        clean, then rebuild' ''

$(STAMP): $(EASY_SOPS) $(MAKEFILE_LIST)
	@rm -rf $(PLAYGROUND)
	mkdir -p $(PLAYGROUND)/secrets $(PLAYGROUND)/config $(PLAYGROUND)/app $(PLAYGROUND)/deploy/prod $(PLAYGROUND)/keys $(PLAYGROUND)/data

	$(AGE_KEYGEN) -o $(PLAYGROUND)/keys/age.txt >/dev/null
	$(AGE_KEYGEN) -o $(PLAYGROUND)/keys/age2.txt >/dev/null
	recipient=$$($(AGE_KEYGEN) -y $(PLAYGROUND)/keys/age.txt)
	recipient2=$$($(AGE_KEYGEN) -y $(PLAYGROUND)/keys/age2.txt)

	printf '%s\n' \
		'# Sample config. Rules are tried in order; the first match wins.' \
		'creation_rules:' \
		'  - path_regex: ^secrets/prod\.yaml$$' \
		'    age: __RECIPIENT__' \
		'  - path_regex: ^secrets/' \
		'    age: __RECIPIENT__,__RECIPIENT2__' \
		'  - path_regex: \.yaml$$' \
		'    age: __RECIPIENT__' \
		'  - path_regex: ^data/' \
		'    age: __RECIPIENT__' \
		> $(PLAYGROUND)/.sops.yaml
	sed -i -e "s|__RECIPIENT2__|$$recipient2|g" -e "s|__RECIPIENT__|$$recipient|g" $(PLAYGROUND)/.sops.yaml

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
		'# matched by the secrets rule, encrypted to one key only while the' \
		'# rule expects two, so `status` reports `need updatekeys`' \
		'scope: updatekeys-demo' \
		> $(PLAYGROUND)/secrets/drift.yaml
	printf '%s\n' \
		'# matched by the catch-all rule (which expects one key) but' \
		'# encrypted to a key the rule does not list, so `status`' \
		'# reports `need rotate`' \
		'scope: rotate-demo' \
		> $(PLAYGROUND)/app/rotate.yaml
	printf '%s\n' \
		'# matched by the dot-yaml catch-all rule, left unencrypted' \
		'debug: false' \
		> $(PLAYGROUND)/app/settings.yaml
	printf '%s\n' \
		'# nested YAML, also caught by the catch-all rule, left unencrypted' \
		'replicas: 3' \
		> $(PLAYGROUND)/deploy/prod/values.yaml
	printf '%s\n' \
		'not matched by any rule, so easy-sops never lists this file' \
		> $(PLAYGROUND)/notes.txt

	head -c 64 /dev/urandom > $(PLAYGROUND)/data/blob.bin

	# sops looks for .sops.yaml relative to the cwd, so point it at the sandbox.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/secrets/prod.yaml
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/secrets/dev.yaml
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --encrypt --in-place $(PLAYGROUND)/config/db.yaml
	# Encrypt to one key only, although the matching rule expects two, so
	# this file shows up as `need updatekeys`.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --age "$$recipient" --encrypt --in-place $(PLAYGROUND)/secrets/drift.yaml
	# Encrypt to the *other* key, which the matching rule does not list, so
	# this file shows up as `need rotate`.
	$(SOPS) --config $(PLAYGROUND)/.sops.yaml --age "$$recipient2" --encrypt --in-place $(PLAYGROUND)/app/rotate.yaml

	touch $(STAMP)
	printf '%s\n' '' 'playground ready in ./$(PLAYGROUND)/' '  encrypted:       secrets/prod.yaml, config/db.yaml' '  multi-key:       secrets/dev.yaml (two keys)' '  need updatekeys: secrets/drift.yaml (one expected key missing)' '  need rotate:     app/rotate.yaml (encrypted to an unexpected key)' '  not encrypted:   secrets/extra.yaml, app/settings.yaml, deploy/prod/values.yaml' '  not matched:     notes.txt' '  filestatus !:    data/blob.bin' '' 'try: make demo'

playground: $(STAMP)

demo: $(STAMP)
	@printf '\n=== root ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) root
	printf '\n=== ls-rules ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) ls-rules
	printf '\n=== ls-files ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) ls-files
	printf '\n=== match secrets/dev.yaml ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) match secrets/dev.yaml
	printf '\n=== match notes.txt (unmatched, exits 1) ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) match notes.txt || true
	printf '\n=== status --branch ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) status --branch
	printf '\n=== status --porcelain ===\n'
	$(EASY_SOPS) -C $(PLAYGROUND) status --porcelain

status: $(STAMP)
	@$(EASY_SOPS) -C $(PLAYGROUND) status

porcelain: $(STAMP)
	@$(EASY_SOPS) -C $(PLAYGROUND) status --porcelain

ls-rules: $(STAMP)
	@$(EASY_SOPS) -C $(PLAYGROUND) ls-rules

ls-files: $(STAMP)
	@$(EASY_SOPS) -C $(PLAYGROUND) ls-files

match: $(STAMP)
	@$(EASY_SOPS) -C $(PLAYGROUND) match $(FILE)

clean:
	@rm -rf $(PLAYGROUND)

reset: clean playground
