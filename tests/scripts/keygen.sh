#!/bin/bash

source ./tests/scripts/func.sh

algs=("RSA1024" "RSA2048" "ECCP256" "ECCP384")
slots=("9a" "9c" "9d" "9e" "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e" "8f" "90" "91" "92" "93" "94" "95")
for alg in ${algs[*]}; do
    for slot in ${slots[*]}; do
        echo -n "  Test ${alg} in slot ${slot}... "
        gen_and_delete ${alg} $slot && echo -e ".\t${OK}" || exit $?
    done
done
