#!/bin/bash -eu

source tests/docker_env.sh
run_in_docker rm -f memory.flash
run_in_docker \
    -e "PICO_OPENPGP_VAULT_ENROLLMENT_JSON=${PICO_OPENPGP_VAULT_ENROLLMENT_JSON:-}" \
    -e "PICO_OPENPGP_VAULT_PASSPHRASE=${PICO_OPENPGP_VAULT_PASSPHRASE:-}" \
    ./tests/start-up-and-test.sh
