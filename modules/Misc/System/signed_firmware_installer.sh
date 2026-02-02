#!/bin/bash

. "${1}"

echo "$INSTALLING"
mv "${3}" "${3}.bak"
cp "${2}" "${3}"
chmod 755 "${3}"
sleep 2
echo "$INSTALLED"


