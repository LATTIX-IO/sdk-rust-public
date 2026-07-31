# --- Symphony orchestration targets ---
SYMPHONY_ROOT ?= E:/lattix/symphony
SYMPHONY_ELIXIR_ROOT ?= $(SYMPHONY_ROOT)/elixir
SYMPHONY_RUST_ROOT ?= $(SYMPHONY_ROOT)/rust
SYMPHONY_WORKFLOW ?= $(CURDIR)/WORKFLOW.md
SYMPHONY_DOTENV_FILE ?= $(or $(wildcard $(CURDIR)/.env.symphony.local),$(wildcard E:/lattix/lattix-monorepo/.env.symphony.local))
SYMPHONY_CODEX_WRAPPER ?= $(CURDIR)/scripts/symphony-codex.sh
SYMPHONY_PORT ?= 4057
MISE_WINGET ?= $(subst \,/,$(USERPROFILE))/AppData/Local/Microsoft/WinGet/Packages/jdx.mise_Microsoft.Winget.Source_8wekyb3d8bbwe/mise/bin/mise.exe
MISE ?= $(if $(wildcard $(MISE_WINGET)),$(MISE_WINGET),mise)
GIT_SH_DIR ?= C:/Program Files/Git/usr/bin
SYMPHONY_RUNNER ?= "$(MISE)" exec -- escript ./bin/symphony
SYMPHONY_NO_GUARDS ?=
SYMPHONY_GITHUB_COPILOT_MODEL ?= gpt-5.4
SYMPHONY_ROUTE ?= $(firstword $(filter native omniroute --native --omniroute,$(MAKECMDGOALS)))
SYMPHONY_ROUTE := $(patsubst --%,%,$(SYMPHONY_ROUTE))
SYMPHONY_ROUTE := $(if $(SYMPHONY_ROUTE),$(SYMPHONY_ROUTE),native)
SYMPHONY_NATIVE_MODEL ?= gpt-5.6-sol
SYMPHONY_OMNIROUTE_MODEL ?= auto
SYMPHONY_REASONING_EFFORT ?= high
OMNIROUTE_VERSION ?= 3.8.48
OMNIROUTE_RUN_ROOT ?= E:/lattix/.omniroute
SYMPHONY_MANAGEMENT_PLANE_URL ?= $(if $(wildcard $(SYMPHONY_ROOT)/management-plane/package.json),http://127.0.0.1:4173,)
SYMPHONY_WINDOWS_ERL_AFLAGS ?= -noinput
SYMPHONY_GUARD_ACK_FLAG ?= --i-understand-that-this-will-be-running-without-the-usual-guardrails
SYMPHONY_LANGUAGE ?= $(firstword $(filter elixir elixer rust all --elixir --elixer --rust --all,$(MAKECMDGOALS)))
SYMPHONY_LANGUAGE := $(patsubst --%,%,$(SYMPHONY_LANGUAGE))
SYMPHONY_LANGUAGE := $(subst elixer,elixir,$(SYMPHONY_LANGUAGE))
SYMPHONY_LANGUAGE := $(if $(SYMPHONY_LANGUAGE),$(SYMPHONY_LANGUAGE),elixir)
SYMPHONY_INFERENCE_SOURCE ?= $(firstword $(filter github-copilot github_copilot copilot codex --github-copilot --github_copilot --copilot --codex,$(MAKECMDGOALS)))
SYMPHONY_INFERENCE_SOURCE := $(patsubst --%,%,$(SYMPHONY_INFERENCE_SOURCE))
SYMPHONY_INFERENCE_SOURCE := $(subst github_copilot,github-copilot,$(SYMPHONY_INFERENCE_SOURCE))
SYMPHONY_INFERENCE_SOURCE := $(if $(filter copilot,$(SYMPHONY_INFERENCE_SOURCE)),github-copilot,$(SYMPHONY_INFERENCE_SOURCE))
SYMPHONY_INFERENCE_SOURCE := $(if $(SYMPHONY_INFERENCE_SOURCE),$(SYMPHONY_INFERENCE_SOURCE),github-copilot)
SYMPHONY_GUARD_SELECTOR := $(firstword $(filter no-guards --no-guards,$(MAKECMDGOALS)))
SYMPHONY_GUARD_ACK := $(if $(SYMPHONY_GUARD_SELECTOR),$(SYMPHONY_GUARD_ACK_FLAG),$(if $(filter 1 true yes on,$(SYMPHONY_NO_GUARDS)),$(SYMPHONY_GUARD_ACK_FLAG),))

.PHONY: symphony symphpny symphony-install symphony-preflight omniroute-install omniroute-start elixir elixer rust all --elixir --elixer --rust --all github-copilot github_copilot copilot codex native omniroute --github-copilot --github_copilot --copilot --codex --native --omniroute no-guards --no-guards
symphony:
ifneq ($(filter install,$(MAKECMDGOALS)),)
	@$(MAKE) --no-print-directory symphony-install SYMPHONY_LANGUAGE="$(SYMPHONY_LANGUAGE)"
else
	@echo "Starting Symphony for $(SYMPHONY_WORKFLOW) on port $(SYMPHONY_PORT) using route $(SYMPHONY_ROUTE)"
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "$$dotenv = '$(SYMPHONY_DOTENV_FILE)'; if ($$dotenv -and (Test-Path -LiteralPath $$dotenv)) { foreach ($$line in Get-Content -LiteralPath $$dotenv) { $$trimmed = $$line.Trim(); if ($$trimmed -eq '' -or $$trimmed.StartsWith('#')) { continue }; $$parts = $$trimmed -split '=', 2; if ($$parts.Length -ne 2) { continue }; $$name = $$parts[0].Trim(); $$value = $$parts[1].Trim(); if (($$value.StartsWith('"') -and $$value.EndsWith('"')) -or ($$value.StartsWith("'") -and $$value.EndsWith("'"))) { $$value = $$value.Substring(1, $$value.Length - 2) }; Set-Item -Path ('Env:' + $$name) -Value $$value } }; $$env:PATH = '$(GIT_SH_DIR);' + $$env:PATH; $$env:SYMPHONY_AGENT_PROVIDER = '$(SYMPHONY_INFERENCE_SOURCE)'; $$env:SYMPHONY_INFERENCE_ROUTE = '$(SYMPHONY_ROUTE)'; $$env:SYMPHONY_CODEX_WRAPPER = '$(SYMPHONY_CODEX_WRAPPER)'; if ([string]::IsNullOrWhiteSpace($$env:SYMPHONY_NATIVE_MODEL)) { $$env:SYMPHONY_NATIVE_MODEL = '$(SYMPHONY_NATIVE_MODEL)' }; if ([string]::IsNullOrWhiteSpace($$env:SYMPHONY_OMNIROUTE_MODEL)) { $$env:SYMPHONY_OMNIROUTE_MODEL = '$(SYMPHONY_OMNIROUTE_MODEL)' }; if ([string]::IsNullOrWhiteSpace($$env:SYMPHONY_REASONING_EFFORT)) { $$env:SYMPHONY_REASONING_EFFORT = '$(SYMPHONY_REASONING_EFFORT)' }; if ([string]::IsNullOrWhiteSpace($$env:SYMPHONY_GH_COPILOT_MODEL)) { $$env:SYMPHONY_GH_COPILOT_MODEL = '$(SYMPHONY_GITHUB_COPILOT_MODEL)' }; if ([string]::IsNullOrWhiteSpace($$env:SYMPHONY_MANAGEMENT_PLANE_URL) -and -not [string]::IsNullOrWhiteSpace('$(SYMPHONY_MANAGEMENT_PLANE_URL)')) { $$env:SYMPHONY_MANAGEMENT_PLANE_URL = '$(SYMPHONY_MANAGEMENT_PLANE_URL)' }; $$env:ERL_AFLAGS = '$(SYMPHONY_WINDOWS_ERL_AFLAGS) ' + $$env:ERL_AFLAGS; Set-Location '$(SYMPHONY_ELIXIR_ROOT)'; & '$(MISE)' exec -- escript ./bin/symphony $(SYMPHONY_GUARD_ACK) '$(SYMPHONY_WORKFLOW)' --port '$(SYMPHONY_PORT)'"
else
	@bash -lc 'if [ -n "$(SYMPHONY_DOTENV_FILE)" ] && [ -f "$(SYMPHONY_DOTENV_FILE)" ]; then set -a; . "$(SYMPHONY_DOTENV_FILE)"; set +a; fi; if [ -z "$${SYMPHONY_MANAGEMENT_PLANE_URL}" ] && [ -n "$(SYMPHONY_MANAGEMENT_PLANE_URL)" ]; then export SYMPHONY_MANAGEMENT_PLANE_URL="$(SYMPHONY_MANAGEMENT_PLANE_URL)"; fi; cd "$(SYMPHONY_ELIXIR_ROOT)" && SYMPHONY_AGENT_PROVIDER="$(SYMPHONY_INFERENCE_SOURCE)" SYMPHONY_INFERENCE_ROUTE="$(SYMPHONY_ROUTE)" SYMPHONY_CODEX_WRAPPER="$(SYMPHONY_CODEX_WRAPPER)" SYMPHONY_NATIVE_MODEL="$${SYMPHONY_NATIVE_MODEL:-$(SYMPHONY_NATIVE_MODEL)}" SYMPHONY_OMNIROUTE_MODEL="$${SYMPHONY_OMNIROUTE_MODEL:-$(SYMPHONY_OMNIROUTE_MODEL)}" SYMPHONY_REASONING_EFFORT="$${SYMPHONY_REASONING_EFFORT:-$(SYMPHONY_REASONING_EFFORT)}" SYMPHONY_GH_COPILOT_MODEL="$${SYMPHONY_GH_COPILOT_MODEL:-$(SYMPHONY_GITHUB_COPILOT_MODEL)}" $(SYMPHONY_RUNNER) $(SYMPHONY_GUARD_ACK) "$(SYMPHONY_WORKFLOW)" --port "$(SYMPHONY_PORT)"'
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

symphony-preflight:
	@powershell -NoProfile -ExecutionPolicy Bypass -File "$(CURDIR)/scripts/Test-SymphonyOrchestration.ps1" -Route "$(SYMPHONY_ROUTE)" -SymphonyRoot "$(SYMPHONY_ROOT)" -DotenvFile "$(SYMPHONY_DOTENV_FILE)"

omniroute-install:
	@npm install --global "omniroute@$(OMNIROUTE_VERSION)"

omniroute-start:
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "$$runRoot = '$(OMNIROUTE_RUN_ROOT)'; New-Item -ItemType Directory -Force -Path $$runRoot | Out-Null; Set-Location -LiteralPath $$runRoot; & omniroute serve"
else
	@mkdir -p "$(OMNIROUTE_RUN_ROOT)" && cd "$(OMNIROUTE_RUN_ROOT)" && omniroute serve
endif

elixir elixer rust all --elixir --elixer --rust --all github-copilot github_copilot copilot codex native omniroute --github-copilot --github_copilot --copilot --codex --native --omniroute no-guards --no-guards:
	@:

ifneq ($(filter symphony symphpny,$(MAKECMDGOALS)),)
ifneq ($(filter install,$(MAKECMDGOALS)),)
.PHONY: install
install:
	@:
endif
endif
# --- End Symphony orchestration targets ---
