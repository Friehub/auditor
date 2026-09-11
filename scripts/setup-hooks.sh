#!/bin/bash
# Frensense Hook Installer
# Links local hooks to the .git directory.

set -e

HOOK_SOURCE="scripts/pre-commit"
HOOK_TARGET=".git/hooks/pre-commit"

if [ ! -d ".git" ]; then
    echo "[ERROR] Not a git repository. Run 'git init' first."
    exit 1
fi

echo "[LINK] Linking $HOOK_SOURCE to $HOOK_TARGET..."
ln -sf --relative "$HOOK_SOURCE" "$HOOK_TARGET"
chmod +x "$HOOK_SOURCE"

echo "[SUCCESS] Git hooks installed successfully."
