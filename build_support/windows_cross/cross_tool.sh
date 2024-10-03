#!/bin/sh

set -e

b=`basename "$0"`

case "$b" in
    x86_64-*)
        export LIB="$WINDOWS_CROSS_X86_64_LIB"
        export INCLUDE="$WINDOWS_CROSS_X86_64_INCLUDE"
        ;;
    aarch64-*)
        export LIB="$WINDOWS_CROSS_AARCH64_LIB"
        export INCLUDE="$WINDOWS_CROSS_AARCH64_INCLUDE"
        ;;
    *)
        >&2 echo "must be used via arch symlink"
        exit 1
        ;;
esac

case "$b" in
    *-cl)
        exec "$WINDOWS_CROSS_CL" "$@"
        ;;
    *-link)
        exec "$WINDOWS_CROSS_LINK" "$@"
        ;;
    *)
        >&2 echo "must be used via tool symlink"
        exit 1
        ;;
esac
