# --- Symphony orchestration targets ---
SYMPHONY_ROOT ?= D:/lattix/symphony
SYMPHONY_ELIXIR_ROOT ?= $(SYMPHONY_ROOT)/elixir
SYMPHONY_RUST_ROOT ?= $(SYMPHONY_ROOT)/rust
SYMPHONY_WORKFLOW ?= $(CURDIR)/WORKFLOW.md
SYMPHONY_PORT ?= 4057
MISE_WINGET ?= $(subst \,/,$(USERPROFILE))/AppData/Local/Microsoft/WinGet/Packages/jdx.mise_Microsoft.Winget.Source_8wekyb3d8bbwe/mise/bin/mise.exe
MISE ?= $(if $(wildcard $(MISE_WINGET)),$(MISE_WINGET),mise)
GIT_SH_DIR ?= C:/Program Files/Git/usr/bin
SYMPHONY_RUNNER ?= "$(MISE)" exec -- escript ./bin/symphony
SYMPHONY_NO_GUARDS ?=
SYMPHONY_GUARD_ACK_FLAG ?= --i-understand-that-this-will-be-running-without-the-usual-guardrails
SYMPHONY_LANGUAGE ?= $(firstword $(filter elixir elixer rust all --elixir --elixer --rust --all,$(MAKECMDGOALS)))
SYMPHONY_LANGUAGE := $(patsubst --%,%,$(SYMPHONY_LANGUAGE))
SYMPHONY_LANGUAGE := $(subst elixer,elixir,$(SYMPHONY_LANGUAGE))
SYMPHONY_LANGUAGE := $(if $(SYMPHONY_LANGUAGE),$(SYMPHONY_LANGUAGE),elixir)
SYMPHONY_GUARD_SELECTOR := $(firstword $(filter no-guards --no-guards,$(MAKECMDGOALS)))
SYMPHONY_GUARD_ACK := $(if $(SYMPHONY_GUARD_SELECTOR),$(SYMPHONY_GUARD_ACK_FLAG),$(if $(filter 1 true yes on,$(SYMPHONY_NO_GUARDS)),$(SYMPHONY_GUARD_ACK_FLAG),))

.PHONY: symphony symphpny symphony-install elixir elixer rust all --elixir --elixer --rust --all no-guards --no-guards
symphony:
ifneq ($(filter install,$(MAKECMDGOALS)),)
	@$(MAKE) --no-print-directory symphony-install SYMPHONY_LANGUAGE="$(SYMPHONY_LANGUAGE)"
else
	@echo "Starting Symphony for $(SYMPHONY_WORKFLOW) on port $(SYMPHONY_PORT)"
ifeq ($(OS),Windows_NT)
	@set "PATH=$(GIT_SH_DIR);%PATH%" && cd "$(SYMPHONY_ELIXIR_ROOT)" && $(SYMPHONY_RUNNER) $(SYMPHONY_GUARD_ACK) "$(SYMPHONY_WORKFLOW)" --port "$(SYMPHONY_PORT)"
else
	@cd "$(SYMPHONY_ELIXIR_ROOT)" && $(SYMPHONY_RUNNER) $(SYMPHONY_GUARD_ACK) "$(SYMPHONY_WORKFLOW)" --port "$(SYMPHONY_PORT)"
endif
endif

symphpny: symphony

symphony-install:
ifeq ($(SYMPHONY_LANGUAGE),elixir)
	@echo "Installing Symphony Elixir dependencies"
	@cd "$(SYMPHONY_ELIXIR_ROOT)" && "$(MISE)" install && "$(MISE)" exec -- mix deps.get && "$(MISE)" exec -- mix escript.build
else ifeq ($(SYMPHONY_LANGUAGE),rust)
	@echo "Installing Symphony Rust dependencies"
	@cd "$(SYMPHONY_RUST_ROOT)" && cargo fetch
else ifeq ($(SYMPHONY_LANGUAGE),all)
	@$(MAKE) --no-print-directory symphony-install SYMPHONY_LANGUAGE=elixir
	@$(MAKE) --no-print-directory symphony-install SYMPHONY_LANGUAGE=rust
else
	@echo "Unsupported Symphony language: $(SYMPHONY_LANGUAGE). Use elixir, rust, or all."
	@exit 2
endif

elixir elixer rust all --elixir --elixer --rust --all no-guards --no-guards:
	@:

ifneq ($(filter symphony symphpny,$(MAKECMDGOALS)),)
ifneq ($(filter install,$(MAKECMDGOALS)),)
.PHONY: install
install:
	@:
endif
endif
# --- End Symphony orchestration targets ---
