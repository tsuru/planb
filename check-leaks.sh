#!/bin/bash -e

go test -c
PLANB_CHECK_LEAKS=1 ./planb.test -check.f TestServeHTTPStressAllLeakDetector
for f in planb_stress_*_mem.pprof; do
    result=$(go tool pprof --top --unit=B --drop_negative --base planb_stress_0_mem.pprof ./planb.test $f)
    hasPlanb=$(echo "$result" | egrep "[1-9][0-9]*.*planb") || true
    val=$(echo "$result" | head -n 1 | grep -o "^[0-9]*")
    if [ -n "$hasPlanb" ] || [[ "$val" -gt 1572864 ]]; then
        echo "Possible leak detected:"
        echo "$result"
        exit 1
    fi
done
echo "No leaks detected."

rm -f planb.test
rm -f planb_stress_*_mem.pprof
