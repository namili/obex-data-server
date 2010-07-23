#!/bin/sh

set -e

if [ -f config.status ]; then
	make maintainer-clean
fi

autoreconf --install --symlink
./configure $@
