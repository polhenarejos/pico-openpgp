#!/bin/bash -eu

/usr/sbin/pcscd &
sleep 2
rm -rf memory.flash
./build_in_docker/pico_openpgp > /dev/null &
pytest tests -W ignore::DeprecationWarning
