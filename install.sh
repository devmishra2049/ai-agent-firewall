#!/usr/bin/env bash
set -e

# AI Agent Firewall Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/devmishra2049/ai-agent-firewall/main/install.sh | bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ┌──────────────────────────────────────────────────────────────┐"
echo "  │  🛡️  AI AGENT FIREWALL — TERMINAL INSPECTOR INSTALLER       │"
echo "  └──────────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is required but not installed.${NC}"
    echo "Please install Node.js (v18 or newer): https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}Error: Node.js 18 or higher is required. Found: $(node -v)${NC}"
    exit 1
fi

INSTALL_DIR="$HOME/.agent-firewall"
REPO_URL="https://github.com/devmishra2049/ai-agent-firewall.git"

echo -e "Installing AI Agent Firewall into ${BOLD}${INSTALL_DIR}${NC}..."

if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR" && git pull origin main --quiet || true
else
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" --quiet
fi

cd "$INSTALL_DIR/cli"

# Optional npm install for watcher dependencies
if [ -f "package.json" ]; then
    npm install --omit=dev --silent 2>/dev/null || true
fi

chmod +x "$INSTALL_DIR/cli/bin/agent-firewall.js"

# Determine target binary directory in order of active PATH preference
TARGET_BIN_DIR=""
if [ -d "/opt/homebrew/bin" ] && [ -w "/opt/homebrew/bin" ]; then
    TARGET_BIN_DIR="/opt/homebrew/bin"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    TARGET_BIN_DIR="/usr/local/bin"
else
    TARGET_BIN_DIR="$HOME/.local/bin"
    mkdir -p "$TARGET_BIN_DIR"
    if [[ ":$PATH:" != *":$TARGET_BIN_DIR:"* ]]; then
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$HOME/.zshrc"
        fi
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.config/fish/config.fish" ]; then
            echo 'fish_add_path $HOME/.local/bin' >> "$HOME/.config/fish/config.fish"
        fi
        export PATH="$PATH:$TARGET_BIN_DIR"
    fi
fi

# Create symlinks for all command aliases
chmod +x "$INSTALL_DIR/bin/agent-firewall.js" 2>/dev/null || true
ln -sf "$INSTALL_DIR/bin/agent-firewall.js" "$TARGET_BIN_DIR/ai-firewall"
ln -sf "$INSTALL_DIR/bin/agent-firewall.js" "$TARGET_BIN_DIR/ai-agent-firewall"
ln -sf "$INSTALL_DIR/bin/agent-firewall.js" "$TARGET_BIN_DIR/aaf"
ln -sf "$INSTALL_DIR/bin/agent-firewall.js" "$TARGET_BIN_DIR/agent-firewall"

echo -e "\n${GREEN}${BOLD}✓ AI Agent Firewall successfully installed!${NC}"
echo -e "Binaries linked to: ${BOLD}$TARGET_BIN_DIR/aaf${NC} (aliases: ${BOLD}ai-firewall${NC}, ${BOLD}agent-firewall${NC})\n"

if [[ ":$PATH:" != *":$TARGET_BIN_DIR:"* ]]; then
    echo -e "${RED}Note: $TARGET_BIN_DIR is not currently in your \$PATH.${NC}"
    echo -e "Add this to your shell config file (~/.zshrc or ~/.bashrc):"
    echo -e "  export PATH=\"\$PATH:$TARGET_BIN_DIR\"\n"
fi

echo -e "${CYAN}${BOLD}Quickstart Commands:${NC}"
echo -e "  ${BOLD}aaf${NC}                  Open interactive 1-terminal coding agent picker"
echo -e "  ${BOLD}aaf run agy${NC}          Launch Google Antigravity CLI inside firewall"
echo -e "  ${BOLD}aaf run claude${NC}       Launch Anthropic Claude Code inside firewall"
echo -e "  ${BOLD}aaf run aider${NC}        Launch Aider AI Pair Programmer inside firewall"
echo -e "  ${BOLD}aaf watch .${NC}          Watch current workspace for rogue agent tool calls"
echo -e "  ${BOLD}aaf test \"code\"${NC}      Test any prompt or payload against behavioral brain"
echo ""
