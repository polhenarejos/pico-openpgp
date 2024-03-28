#!/bin/bash

source ./tests/scripts/func.sh
echo "==== Test version ===="
./tests/scripts/version.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test asymmetric keygen ===="
./tests/scripts/keygen.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test self-signed certificates ===="
./tests/scripts/signatures.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}

echo "==== Test attestation ===="
./tests/scripts/attestation.sh
test $? -eq 0 || {
    echo -e "\t${FAIL}"
    exit 1
}
