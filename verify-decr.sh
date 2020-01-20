#!/bin/sh

checksum () {
    b2sum -l 128 | awk '{print $1}'
}


# Encrypts the plain in f using key
encr () {
    hexkey="$1"
    f="$2"
    #keyhex=$( dd status=none bs=16 count=1 if="$f" | xxd -p )
    cat "$f" |
        openssl enc -aes-128-ecb -nosalt -nopad -K "$hexkey"
}

# Decrypts the cipher in stdin using key
decr () {
    hexkey="$1"
    ( echo "$hexkey" | xxd -p -r ; cat ) | "$ex"
}

ex=$1

if ! [ -x "$ex" ]; then
    echo "No executable: '$ex'"
    exit 1
fi

hexkey=$( rnd -x 16 )
rnd $((16*10000)) >rnd-dat

plain_checksum=$( checksum <rnd-dat )
decr_checksum=$( encr "$hexkey" rnd-dat | decr "$hexkey" | checksum )

red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'
if [ "$plain_checksum" = "$decr_checksum" ]; then
    # shellcheck disable=SC2059
    printf "${green}OK${reset}\n"
else
    # shellcheck disable=SC2059
    printf "${red}BAD${reset}\n"
    printf 'openssl\n%s\n' "$ex"
    echo "$plain_checksum"
    echo "$decr_checksum"
fi
