#!/usr/bin/env bash
# Set repo-local git identity and the hooks path, then print all three.
set -euo pipefail

git config user.name "Chaitanya Laxman"
git config user.email "54215105+claxman@users.noreply.github.com"
git config core.hooksPath .githooks

echo "user.name=$(git config --get user.name)"
echo "user.email=$(git config --get user.email)"
echo "core.hooksPath=$(git config --get core.hooksPath)"
