#!/bin/sh

set -e

MESSAGE=$(git log --format=%B -n 1 HEAD |awk -F "[" '{print $2}' |awk -F "]" '{print $1}')

if [ "$MESSAGE"x = "skip clippy"x ]; then
    echo "skip clippy"
else
    rustup component add clippy-preview
    cargo clippy
fi
