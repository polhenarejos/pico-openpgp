#!/bin/bash

source ./tests/scripts/func.sh

echo -n "  Fetch attestation certificate... "
piv read-cert -sf9 -o sf9.pem
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

algs=("RSA1024" "RSA2048" "ECCP256" "ECCP384")
slots=("9a" "9c" "9d" "9e" "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e" "8f" "90" "91" "92" "93" "94" "95")
for alg in ${algs[*]}; do
    for slot in ${slots[*]}; do
        echo "  Test attestation with ${alg} in slot ${slot}"
        echo -n "    Keygen... "
        gen_and_check $alg $slot && echo -e ".\t${OK}" || exit $?

        echo -n "    Fetch attesting certificate... "
        piv attest -s$slot -o attestation.pem
        test $? -eq 0 && echo -e ".\t${OK}" || exit $?

        echo -n "    OpenSSL verify attestation... "
        e=$(openssl verify -CAfile sf9.pem attestation.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q ": OK" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    Key deletion... "
        delete_key $alg $slot && echo -e ".\t${OK}" || exit $?

    done
done

rm -rf cert.pem
rm -rf sf9.pem
