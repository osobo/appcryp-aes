#!/bin/sh

f=$1

if ! [ -x "$f" ]; then
    echo "No exec: $f"
    exit 1
fi

go () {
    dd status=progress if=/dev/zero bs=$((16*1000)) count=10000 |
        "$1" >/dev/null 2>&1
}

time go "$f"
