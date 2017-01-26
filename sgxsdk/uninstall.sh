#!/usr/bin/env bash

# Removing the SDK folder
rm -fr /home/cheng/sgxsdk 2> /dev/null

if [ $? -ne 0 ]; then
    echo "Superuser privilege is required."
    exit 1
fi

