#!/bin/sh

set -e

# Add entitlements for using hypervisor framework.
entitlements=$(dirname "$0")/entitlements.xml
codesign --entitlements "$entitlements" -f -s - "$1" > /dev/null
exec "$@"
