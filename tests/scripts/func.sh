#!/bin/bash

OK="\033[32mok\033[0m"
FAIL="\033[31mfail\033[0m"

READER="u"

piv() {
    yubico-piv-tool -r${READER} -a$@
}

gen_and_check() {
    e=$(piv generate -s$2 -A$1 -opublic.pem 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "Successfully generated a new private key" <<< $e && echo -n "." || exit $?
    e=$(piv status 2>&1)
    e=${e//$'\t'/}
    e=${e//$'\n'/}
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "Slot $2:Algorithm:$1" <<< $e && echo -n "." || exit $?
}
delete_key() {
    piv delete-key -s$2 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    piv delete-cert -s$2 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    e=$(piv status 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
    q=$(grep -q "Slot $2: Algorithm: $1" <<< $e)
    test $? -eq 1 && echo -n "." || exit $?
    rm -rf public.pem
}
gen_and_delete() {
    gen_and_check $1 $2
    test $? -eq 0 && echo -n "." || exit $?
    delete_key $1 $2
    test $? -eq 0 && echo -n "." || exit $?
}
