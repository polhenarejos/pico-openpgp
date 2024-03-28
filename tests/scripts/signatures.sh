#!/bin/bash

source ./tests/scripts/func.sh

algs=("RSA1024" "RSA2048" "ECCP256" "ECCP384")
slots=("9a" "9c" "9d" "9e" "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e" "8f" "90" "91" "92" "93" "94" "95")
for alg in ${algs[*]}; do
    for slot in ${slots[*]}; do
        echo "  Test signature with ${alg} in slot ${slot}"
        echo -n "    Keygen... "
        gen_and_check $alg $slot && echo -e ".\t${OK}" || exit $?

        echo -n "    Test request certificate... "
        e=$(piv verify -arequest -P123456 -s$slot -S'/CN=bar/OU=test/O=example.com/' -ipublic.pem -ocert.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q "Successfully verified PIN" <<< $e && echo -n "." || exit $?
        grep -q "Successfully generated a certificate request" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    OpenSSL verify request... "
        e=$(openssl req -verify -in cert.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q " OK" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    Test self-signed certificate... "
        e=$(piv verify -aselfsign -P123456 -s$slot -S'/CN=bar/OU=test/O=example.com/' -ipublic.pem -ocert.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q "Successfully verified PIN" <<< $e && echo -n "." || exit $?
        grep -q "Successfully generated a new self signed certificate" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    Test signature... "
        e=$(piv verify-pin -atest-signature -s$slot -P123456 -icert.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q "Successful" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    OpenSSL verify cert... "
        e=$(openssl verify -CAfile cert.pem cert.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q ": OK" <<< $e && echo -e ".\t${OK}" || exit $?

        echo -n "    Key deletion... "
        delete_key $alg $slot && echo -e ".\t${OK}" || exit $?

    done
done

rm -rf cert.pem
