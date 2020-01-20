#!/bin/sh

checksum () {
    b2sum -l 128 | awk '{print $1}'
}

check_openssl () {
    f=$1
    keyhex=$( dd status=none bs=16 count=1 if="$f" | xxd -p )
    dd status=none bs=16 skip=1 if="$f" |
        openssl enc -aes-128-ecb -nosalt -nopad -K "$keyhex" |
        checksum
}

ex=$1

if ! [ -x "$ex" ]; then
    echo "No executable: '$ex'"
    exit 1
fi

rnd $((16*10000+16)) >rnd-dat

s1=$( check_openssl rnd-dat )
s2=$( "$ex" <rnd-dat 2>/dev/null | checksum )

red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'
if [ "$s1" = "$s2" ]; then
    # shellcheck disable=SC2059
    printf "${green}OK${reset}\n"
else
    # shellcheck disable=SC2059
    printf "${red}BAD${reset}\n"
    printf 'openssl\n%s\n' "$ex"
    echo "$s1"
    echo "$s2"
fi
