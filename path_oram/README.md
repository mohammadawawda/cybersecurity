# Path ORAM

A non recursive Path ORAM. The client keeps its data on an untrusted server, in an encrypted binary tree of buckets. Every read or write touches one full random path of the tree, so the server can't tell which block the client asked for.

Every block is encrypted with AES in GCM mode with a fresh nonce, and the client keeps SHA256 version hashes, so it notices if the server changes the data or rolls it back to an old version.

## Files

* `path_oram.py` the server, the client and `create_oram`
* `benchmarks.py` measures throughput, latency, bandwidth overhead and stash size
* `design_document.pdf` the design, the threat model and the benchmark results

## How to run

```
pip install -r requirements.txt
python benchmarks.py
```
