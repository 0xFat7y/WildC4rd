#!/usr/bin/env bash
# W!ldC4rd v2 — optional dependency installer
# Installs the external tools used by wildcard.py.
# Authorized security testing and asset inventory only.
set -uo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; RESET='\033[0m'
info() { printf '%b[INFO]%b  %s\n' "$CYAN" "$RESET" "$*"; }
ok()   { printf '%b[OK]%b    %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%b[WARN]%b  %s\n' "$YELLOW" "$RESET" "$*"; }
err()  { printf '%b[ERROR]%b %s\n' "$RED" "$RESET" "$*" >&2; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$HOME/.local/bin:$GOPATH/bin:$PATH"

run_sudo() {
    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
    fi
}

install_apt_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get not found; skipping Debian/Ubuntu system packages"
        return
    fi
    info "Installing system packages"
    if ! run_sudo apt-get update -qq; then
        warn "apt update failed; continuing with existing packages"
    fi
    if ! run_sudo apt-get install -y -qq git python3 python3-pip whois ca-certificates; then
        warn "some system packages could not be installed"
    else
        ok "system packages ready"
    fi
}

pip_install() {
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found; cannot install Python dependencies"
        return 1
    fi
    # --break-system-packages is required by some Debian/Ubuntu PEP 668 setups.
    if python3 -m pip install --user --break-system-packages "$@" --quiet; then
        return 0
    fi
    if python3 -m pip install --break-system-packages "$@" --quiet; then
        return 0
    fi
    warn "Python dependency installation failed: $*"
    return 1
}

install_go_tool() {
    local name="$1" package="$2"
    if command -v "$name" >/dev/null 2>&1; then
        ok "$name already available at $(command -v "$name")"
        return 0
    fi
    if ! command -v go >/dev/null 2>&1; then
        warn "Go is unavailable; skipped $name"
        return 0
    fi
    info "Installing $name"
    if go install "$package"; then
        ok "$name installed"
    else
        warn "$name installation failed; continuing"
    fi
}

clone_or_update() {
    local repo="$1" destination="$2"
    mkdir -p "$(dirname "$destination")"
    if [[ -d "$destination/.git" ]]; then
        if git -C "$destination" pull --ff-only >/dev/null 2>&1; then
            ok "updated $(basename "$destination")"
        else
            warn "could not update $(basename "$destination"); using existing checkout"
        fi
        return 0
    fi
    if [[ -e "$destination" ]]; then
        warn "$destination exists but is not a git checkout; leaving it untouched"
        return 1
    fi
    if git clone --depth 1 "$repo" "$destination"; then
        ok "cloned $(basename "$destination")"
        return 0
    fi
    warn "clone failed: $repo"
    return 1
}

install_xnlinkfinder() {
    local dir="$HOME/tools/xnLinkFinder"
    local script="$dir/xnLinkFinder.py"
    if [[ ! -f "$script" ]]; then
        clone_or_update "https://github.com/xnl-h4ck3r/xnLinkFinder.git" "$dir" || return
    fi
    if [[ -f "$dir/requirements.txt" ]]; then
        pip_install -r "$dir/requirements.txt" || true
    fi
    mkdir -p "$HOME/.local/bin"
    if [[ -f "$script" ]]; then
        chmod +x "$script" 2>/dev/null || true
        ln -sfn "$script" "$HOME/.local/bin/xnLinkFinder"
        ok "xnLinkFinder available at $HOME/.local/bin/xnLinkFinder"
    fi
}

install_eyewitness() {
    if command -v eyewitness >/dev/null 2>&1 || command -v EyeWitness >/dev/null 2>&1; then
        ok "EyeWitness already available"
        return
    fi
    if command -v apt-cache >/dev/null 2>&1 && apt-cache show eyewitness >/dev/null 2>&1; then
        info "Installing EyeWitness from apt"
        if run_sudo apt-get install -y -qq eyewitness; then
            ok "EyeWitness installed from apt"
            return
        fi
        warn "apt EyeWitness install failed; trying the official source"
    fi

    local dir="$HOME/tools/EyeWitness"
    if clone_or_update "https://github.com/RedSiege/EyeWitness.git" "$dir"; then
        local requirements=""
        if [[ -f "$dir/Python/requirements.txt" ]]; then
            requirements="$dir/Python/requirements.txt"
        elif [[ -f "$dir/Python3/requirements.txt" ]]; then
            requirements="$dir/Python3/requirements.txt"
        fi
        if [[ -n "$requirements" ]]; then
            pip_install -r "$requirements" || true
        fi
        ok "EyeWitness source available at $dir"
    fi
}

install_gf_patterns() {
    local destination="$HOME/.gf"
    local temporary
    mkdir -p "$destination"
    temporary="$(mktemp -d)"
    if clone_or_update "https://github.com/1ndianl33t/Gf-Patterns.git" "$temporary/Gf-Patterns"; then
        if compgen -G "$temporary/Gf-Patterns/*.json" >/dev/null 2>&1; then
            cp -f "$temporary/Gf-Patterns"/*.json "$destination/"
            ok "GF patterns installed in $destination"
        else
            warn "GF pattern repository contained no JSON patterns"
        fi
    fi
    rm -rf "$temporary"
}

install_apt_packages

info "Installing Python dependency used by W!ldC4rd"
pip_install -r "$SCRIPT_DIR/requirements.txt" || true

# Go tools used by v2. uro is intentionally not installed: v2 performs
# scope-aware normalization and deduplication itself.
install_go_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool amass        "github.com/owasp-amass/amass/v4/...@latest"
install_go_tool assetfinder  "github.com/tomnomnom/assetfinder@latest"
install_go_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool waybackurls  "github.com/tomnomnom/waybackurls@latest"
install_go_tool gau          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool gf           "github.com/tomnomnom/gf@latest"
install_go_tool katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
install_gf_patterns
install_xnlinkfinder
install_eyewitness

cat <<EOF

${GREEN}[OK]${RESET} Installation pass finished.

Make sure these directories are on PATH:
  $HOME/.local/bin
  $GOPATH/bin

If needed, add this to ~/.bashrc or ~/.zshrc:
  export PATH="\$HOME/.local/bin:\$HOME/go/bin:\$PATH"

Then run the tool from the repository:
  python3 wildcard.py
EOF
