#!/bin/bash
# Summarize notes in the user-selected folder passed as $1.
set -euo pipefail
TARGET="${1:?usage: summarize.sh <folder>}"
find "$TARGET" -maxdepth 1 -name '*.md' -print
