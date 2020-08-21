#!/bin/bash

if [ -n "${DBG}" ]; then
    set -x
fi;

if [ -z "${1}" ]; then
    echo "You should provide an UUID"
fi;

let "i=0"

echo -n '' > ${1}.b64

while [ 1 ]; do
    data="$(dig @127.0.0.1 -p 5354 ${i}.${1}.foo.com TXT +short | tr -d \")"
    if [ -z "${data}" ]; then break; fi;
    echo ${data} >> ${1}.b64
    let "i=i+1"
done;

base64 -d < ${1}.b64 > ${1}
rm ${1}.b64
