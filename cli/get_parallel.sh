#!/bin/bash

_jobs=${JOBS:-50}

if [ -n "${DBG}" ]; then set -x; fi;
if [ -z "${1}" ]; then echo "You should provide an UUID"; exit 1; fi;
if [ -f "${1}.b64" ]; then rm "${1}.b64"; fi;

hash="$(dig @127.0.0.1 -p 5354 hash.${1}.foo.com TXT +short | tr -d \")"
chunks="$(dig @127.0.0.1 -p 5354 chunks.${1}.foo.com TXT +short | tr -d \")"

echo "Downloading ${1} with ${_jobs} concurent jobs"

parallel --jobs ${_jobs} -a <(seq 0 $(( ${chunks} - 1)) ) -a <(echo ${1}) 'echo {1} $(dig @127.0.0.1 -p 5354 {1}.{2}.foo.com TXT +short | tr -d \")' | sort -n | cut -d\  -f2 | tr -d '\n' > ${1}.b64

sum=$(sha1sum "${1}.b64" | awk '{print $1}')
if [ "${sum}" != "${hash}" ]; then
    echo "WARNING the sha1sum of the retrieved file does not match the one from the server";
    echo "Got ${sum} wanted ${hash}"
fi;

base64 -d < ${1}.b64 > ${1} && rm ${1}.b64
if [ -n "${2}" ]; then mv "${1}" "${2}"; fi;
