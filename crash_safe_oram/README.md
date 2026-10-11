# crash safe ORAM

in Path ORAM the position map and the stash live only on the client. if the client crashes in the middle of an access, the client and the server go out of sync and data can be lost.
we added a write ahead log, so after a restart the client can finish or undo the access it was in. the recovery itself is built so it doesn't show the server which path was accessed.

the full design is in design_document.pdf.

## how to run

python 3.9 or newer. dependency: pycryptodome (AES-GCM)

can be installed with :
```
pip install -r requirements.txt
```

the program uses https protocol to communicate with the server, to make self signed certificates(local host):
```
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

on Windows run it with "-subj "//CN=localhost" " (two slashes).

to check, the command `openssl x509 -in certs/cert.pem -noout -text`
must show "DNS:localhost, IP Address:127.0.0.1"

cert.pem is public, key.pem is private.

to run the test file:
```
python -m unittest discover -s tests -v
```

to run the crashtest:
```
python crashtest.py --spawn-server --runs 300 --ops 60 -L 10
```

each run:
1. resets the server and creates a fresh client state.
2. runs a random workload in a child process that crashes at a random point of a random access (half of the runs as a simulated power cut).
3. in half of the runs, crashes a second child in the middle of the recovery write.
4. recovers in the test process itself, finishes the workload and reads everything back.
5. checks in the server's trace that the recovery sent at most one request, a write to a leaf the server had already seen.
6. reopens the client once more and reads everything again.

it ends with a table per crash point and `all N runs passed`.

to run the benchmark:
```
python bench.py --spawn-server --sweep
```
