#!/bin/bash

chmod a+x tests/scripts/*.sh

echo "======== CLI Test suite ========"
./tests/scripts/yubico-piv-tool.sh
