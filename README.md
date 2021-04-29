# dnsbin2 - Pastebin over DNS
> Because [dnsbin](https://github.com/thomas-maurice/dnsbin) was not stupid enough.

# TL;DR
This is a (slightly) improved re-implementation of my already embarassingly stupid and useless [dnsbin](https://github.com/thomas-maurice/dnsbin) written in Go.

The main advantages are:
* I does not embed a f*cking BIND server inside the docker image
* It can delete uploaded files (I don't know if the previous version was able to but tbh my eyes started bleeding when I read the code so we'll never know)
* You can make the retrieving of the files concurrent, so it can be both utterly useless and very fast, just like the software equivalent of [sanic](https://knowyourmeme.com/memes/sanic-hegehog)

In terms of features it is fairly simple, it allows you to:
* Upload a file for storage using a simple cURL command
* Delete the file with the generated signed token
* Retrieves this file using a state of the art base64-over-DNS-TXT-fields API

At this moment you are probably rightfully wondering these three things:
1. Why would I ever use something like that ?
2. Why did you commit such attrocity ?
3. u ok dude ?

To which I would answer
1. Because you want to sneakily get files on a monitored network that unexpicably allows yolo DNS traffic, or more likely because you either hate your self or are high as f*ck.
2. Because I can, there is nothing you can do about it and I exist to spite God.
3. Writing this code gave me brain damage.

*Disclaimer*: The code **IS** horrendous, untested and bad, and I don't care the slightest.

# Cool story bro, how do I use it ?
## Compile it
```bash
$ make
if ! [ -d bin ]; then mkdir bin; fi
go build -v -o ./bin/server ./server
go build -v -o ./bin/cli ./cli

```
## Run the server
```
$ ./bin/server -listen :5354
INFO[0000] creating the files directory
INFO[0000] you can upload a file doing something like curl -F 'file=@some-file.txt' http://localhost:8080/upload
INFO[0000] creating the keys directory
INFO[0000] generating new ed25519 signing keys
```

All the data will live in a new `./data` directory.

## Upload some file
```json
$ curl -sF 'file=@server/main.go' http://localhost:8080/upload | jq .
{
  "error": false,
  "error_msg": "",
  "uuid": "755c6d53-6fee-4221-bfa7-b9f76aa79f8e",
  "size": 12152,
  "sha1": "40cb4c5136e045bfac72b90ca43f097a8ed32823",
  "delete_token": "eyJzaWduYXR1cmUiOiI2MWQ3NzVlMmU5ZWE1ODk4ZjVhYzk1NjM5MGU2MWU0NWNmN2ViODYyOWJhNjdmZDE1MTZiYTcxMjQ3YmExMDE5YTMyMTA0MjI5YzlhMGFiNDJmZDdhYjU2MGY0NjU3OGEzMGM2MWRlNzFkYmM4MTM2MDRhN2Q0MzAzYWQyZmUwYyIsImZpbGVfaWQiOiI3NTVjNmQ1My02ZmVlLTQyMjEtYmZhNy1iOWY3NmFhNzlmOGUifQ=="
}
```
Note the `uuid` and `delete_tokens` you will need for later, you can also store the sha1 to check for file integrity.

## Retrieve some file
```bash
$ ./bin/cli -resolver 127.0.0.1:5354 -domain does.not.matter.if.locally -uuid 755c6d53-6fee-4221-bfa7-b9f76aa79f8e
...
[the content of the file so if it binary i strongly suggest to pipe it somewhere otherwise it will fuck up your terminal]
...
```

Funnily enough you can also achieve the same exact thing using a bash script that would go something like that
```bash
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
```

You can also do it in parallel with something like that (needs GNU/parallel)
```bash
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
```

## Delete some file
Do a `curl` call to the `/delete` endpoint using the `delete_token` value you got previously. This is a signed token that will allow you to delete whatever stuff you uploaded.

```bash
$ curl 'http://localhost:8080/delete?token=eyJzaWduYXR1cmUiOiI2MWQ3NzVlMmU5ZWE1ODk4ZjVhYzk1NjM5MGU2MWU0NWNmN2ViODYyOWJhNjdmZDE1MTZiYTcxMjQ3YmExMDE5YTMyMTA0MjI5YzlhMGFiNDJmZDdhYjU2MGY0NjU3OGEzMGM2MWRlNzFkYmM4MTM2MDRhN2Q0MzAzYWQyZmUwYyIsImZpbGVfaWQiOiI3NTVjNmQ1My02ZmVlLTQyMjEtYmZhNy1iOWY3NmFhNzlmOGUifQ=='
{"error":false,"error_msg":"","ok":true}
```

# How does it work ?
## Uploading
The uploading is straightforward. The server accepts a file, base64 encodes it, hashes it, assigns it an ID (UUID in our case) then signes its UUID (to create the deletion token) with an ed25519 key generated by the server and returns all of that to the user. The signed UUID is here used as a token to ensure that only the user that uploaded the file can delete it via the API (otherwise a goode ole `rm` works fine too)

## Retrieving the file
This is the funniest part. As you might know if you attended school one day in your life, DNS is trash, yet I am leveraging the TXT records of the protocol to make transit arbitrary data over the wire, however these fields are limited to a length of 255 bytes.

To manage to retrieve the file entirely the cli will retrieve small chunks of 255 bytes each and reassemble them. This is done by querying sequentially the following domain `<chunkID>.<fileUUID>.domain.wtf` and getting the value of the TXT field, until the servers sends us an `NXDOMAIN` error, that we use here as the good olde `EOF`.

Then concatenate all that and base64-decode it and bam you have your original file.

# Getting file infos
You can query the special `chunks` and `hash` subdomains to fetch the SHA1 of the file and the number of chunks that will be required to download it.
```bash
$ dig @127.0.0.1 -p 5354 chunks.04927d90-1c30-4e15-bdde-6b714ea1326c.foo.com. TXT +short
"27522"
$ dig @127.0.0.1 -p 5354 hash.04927d90-1c30-4e15-bdde-6b714ea1326c.foo.com. TXT +short
"b27c33435ebf8313104fe6fdf757ef0a56a2a5c5"
```

# How about the performance
I'm so glad you asked. Let us demonstrate with a simple 5Mb file.

Let's start by generating a file
```bash
$ dd if=/dev/urandom of=file bs=1M count=5
5+0 records in
5+0 records out
5242880 bytes (5.2 MB, 5.0 MiB) copied, 0.0572735 s, 91.5 MB/s
```

Let's upload it
```bash
$ time ( curl -sF 'file=@file' http://localhost:8080/upload | jq . )
{
  "error": false,
  "error_msg": "",
  "uuid": "bbeff5b7-f0bb-49ef-ab90-e65fb83fa66b",
  "size": 6990508,
  "sha1": "af575237058e95514080a662c3c0abd41abca3a8",
  "delete_token": "eyJzaWduYXR1cmUiOiIyN2FmZGEyZjRjZjQyYzkyMDU2Y2Q0ZTIwYzU2N2Q4NzFkMTlhNGVhNmRlYjc1YzQ0ZTk0ODg1ZDcwZmJiNmYwNTU0NmUyODkxNWU5MWM1OWFhZWJiYTFmNWExYzZiZDdiZWRkNjdmZmE4M2NmYTMyYzIxNzMzYWQ5YTdlZTIwMCIsImZpbGVfaWQiOiJiYmVmZjViNy1mMGJiLTQ5ZWYtYWI5MC1lNjVmYjgzZmE2NmIifQ=="
}

real    0m0.088s
user    0m0.077s
sys     0m0.029s
```

And now let's retrieve it :)))))
```bash
time ( ./bin/cli -resolver 127.0.0.1:5354 -domain does.not.matter -uuid bbeff5b7-f0bb-49ef-ab90-e65fb83fa66b > /dev/null )

real    0m19.979s
user    0m37.066s
sys     0m6.089s
```

Yep, that's shit alright.

**EDIT**: You can now make the cli retrieve the file chunks in a parallel way. With a concurency of 30 (`-workers 30`) it downloads
the 5M of data in less than a second locally.

# In conclusion
Being able to do something does **NOT** mean that you should do it.
