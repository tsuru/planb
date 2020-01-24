#!/bin/sh
touch /tmp/access.log
tail -f /tmp/access.log &
exec /bin/planb $@
