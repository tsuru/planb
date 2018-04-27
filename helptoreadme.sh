#!/bin/bash

planb --help | grep "GLOBAL OPTIONS" -A 1000 | tail +2 | sed -E 's/^ *(((-[^ ]*)( value)?(, )?)+) */- `\1`: /' | sed -E 's/^ +/  /'
