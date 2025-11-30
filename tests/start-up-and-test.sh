#!/bin/bash

OK="\t\033[32mok\033[0m"
FAIL="\t\033[31mfail\033[0m"

fail() {
    echo -e "${FAIL}"
    exit 1
}

echo -n "Start PCSC..."
/usr/sbin/pcscd &
test $? -eq 0 && echo -e "${OK}" || {
    echo -e "${FAIL}"
    exit 1
}
sleep 1
rm -f memory.flash
echo -n "Start Pico OpenPGP..."
./build_in_docker/pico_openpgp > /dev/null 2>&1 &
PID=$!
test $? -eq 0 && echo -n "." || fail
sleep 1
ATR="3b:da:18:ff:81:b1:fe:75:1f:03:00:31:f5:73:c0:01:60:00:90:00:1c"
e=$(opensc-tool -an 2>&1)
grep -q "${ATR}" <<< $e && echo -n "." || fail
test $? -eq 0 && echo -e "${OK}" || fail

pytest tests -W ignore::DeprecationWarning

echo -n "Stopping Pico OpenPGP..."
kill "$PID" 2>/dev/null || true
kill -9 "$PID" 2>/dev/null || true
test $? -eq 0 && echo -e "${OK}" || fail
sleep 1
rm -f memory.flash
echo -n "Start Pico OpenPGP..."
./build_in_docker/pico_openpgp > /dev/null 2>&1 &
PID=$!
test $? -eq 0 && echo -n "." || fail
sleep 1
e=$(opensc-tool -an 2>&1)
grep -q "${ATR}" <<< $e && echo -n "." || fail
test $? -eq 0 && echo -e "${OK}" || fail

./tests/scripts/cli-test.sh
