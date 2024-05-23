#!/bin/bash

source ./tests/scripts/func.sh

# Get version
echo -n "  Test version... "
e=$(piv version 2>&1)
test $? -eq 0 && echo -n "." || exit $?
grep -q "Application version" <<< $e && echo -n "." || exit $?
grep -q " found" <<< $e && echo -e ".\t${OK}" || exit $?
