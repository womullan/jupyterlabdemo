#!/bin/sh
# Source virtualenvwrapper.sh
if [ $(id -u) -ne 0 ]; then
    source /usr/bin/virtualenvwrapper.sh
    rc=$?
    if [ "${rc}" -ne 0 ]; then
	alias python='python3'
	source /usr/bin/virtualenvwrapper.sh
	unalias python
    fi
fi

