"""this is the server code
    it stores the encrypted tree (client's data) , answers the requests (read/write/delete/reset)
    over https.
    in order to test the program locally, we generated a self signed certificate with openssl using the following
    website https://www.baeldung.com/openssl-self-signed-cert.
    needed only once (no need to run the command each run)
    the commands needed in windows :
    mkdir certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout certs/key.pem -out
    certs/cert.pem -subj "//CN=localhost" -addext
    "subjectAltName=DNS:localhost,IP:127.0.0.1"
    IT WORKS if:
    the command  openssl x509 -in certs/cert.pem -noout -text
    GIVES  DNS:localhost, IP Address:127.0.0.1
"""


import argparse
import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Server:
    def __init__(self,height, bucket_size=4):
        """
        Initialize the server with an empty tree.

        Args:
            height: Tree height L. The tree has 2^L leaves.
            bucket_size: Number of slots per bucket (Z), Default = 4.

        """
        self.lock = threading.Lock()
        self.reset(height, bucket_size)

    def reset(self,height,bucket_size):
        """Empty the tree, the trace and the counters. does not replace the lock."""
        self.height = height
        self.bucket_size = bucket_size
        self.num_leaves = 2 ** height
        self.total_nodes = 2 ** (height + 1) - 1
        self.tree = [None] * self.total_nodes

        self.trace = []
        self.event_counter = 0

        self.reads = 0
        self.writes = 0
        self.bytes_in = 0
        self.bytes_out = 0
    def node_index(self,leaf,level):
        """
        get the index in the tree array of the bucket at the given level on the path to leaf.
        """
        return (2 ** level - 1) + (leaf >> (self.height - level))

    def get_path(self,leaf):
        """
        given a leaf, returns a list of the path from root to that leaf

        """
        if leaf<0 or leaf>=self.num_leaves :
            raise ValueError("Leaf index out of range")
        path= [self.node_index(leaf,level) for level in range(self.height +1) ]
        return path

    def bucket_bytes(self, bucket):
        """
        number of real bytes in a bucket, each slot is a hex string (2 chars per byte).
        """
        if bucket is None:
            return 0
        return sum(len(s) // 2 for s in bucket if s is not None)

    def read_path(self, leaf):
        """
        returns the buckets on the path to leaf, root first.
        """
        path = [self.tree[index] for index in self.get_path(leaf)]
        num_bytes = sum(self.bucket_bytes(bucket) for bucket in path)

        self.reads += 1
        self.bytes_out += num_bytes
        self.record("read", leaf, 0, len(path), num_bytes)
        return path

    def write_path(self, leaf, start, buckets):
        """
        overwrite the buckets on the path to leaf, starting from level start.
        checks everything first, so a bad request changes nothing.
        """
        path = self.get_path(leaf)
        if start < 0 or start + len(buckets) > self.height + 1:
            raise ValueError("Write range out of path")
        for bucket in buckets:
            if len(bucket) > self.bucket_size:
                raise ValueError("Bucket has more than Z slots")

        num_bytes = 0
        for i, bucket in enumerate(buckets):
            self.tree[path[start + i]] = bucket
            num_bytes += self.bucket_bytes(bucket)

        self.writes += 1
        self.bytes_in += num_bytes
        self.record("write", leaf, start, len(buckets), num_bytes)

    def record(self, op, leaf, start, count, num_bytes):
        """
        add one event to the trace (what the server sees).
        """
        self.event_counter += 1
        self.trace.append({
            "seq": self.event_counter,
            "op": op,
            "leaf": leaf,
            "from": start,
            "count": count,
            "bytes": num_bytes,
            "unix_nano": time.time_ns(),
        })

    def stats(self):
        """
        the counters, without the list of events.
        """
        return {
            "events": len(self.trace),
            "reads": self.reads,
            "writes": self.writes,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }



def make_handler(server):
    """
    returns the Handler class, all handlers share the same server object.
    """

    class Handler(BaseHTTPRequestHandler):
        # keep the connection open between requests
        protocol_version= "HTTP/1.1"
        # send small replies right away (wuithout delay)
        disable_nagle_algorithm= True

        def log_message(self,*args):
            """
            do not print a line for every request.
            """
            pass

        def send_json(self,obj,status=200):
            """
            send obj as a json reply.
            """
            body= json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_error_text(self,message,status=400):
            """
            send an error message as text.
            """
            body= message.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_json(self):
            """
            read the request body and parse it.
            """
            length= int(self.headers.get("Content-Length", 0))
            raw= self.rfile.read(length) if length>0 else b""
            return json.loads(raw) if raw else {}

        def do_GET(self):
            """
            allow GET too
            """
            self.do_POST()

        def do_POST(self):
            """
            handle one  request: parse it, lock,call the server, reply.
            """
            try:
                request=  self.read_json()
            except ValueError as e:
                return self. send_error_text(f"Bad JSON: {e}")

            with server.lock:
                try:
                    if self.path=="/read" :
                        buckets=server.read_path(int(request["leaf"]))
                        return self.send_json({"buckets": buckets})

                    if self.path=="/write" :
                        server.write_path(int(request["leaf"]),int(request.get("from", 0)),request["buckets"])
                        return self.send_json({"ok": True})

                    if self.path=="/reset" :
                        server.reset(int(request["L"]),int(request["Z"]))
                        print(f"reset: L={server.height} Z={server.bucket_size}", flush=True)
                        return self.send_json({"ok": True})

                    if self.path=="/params" :
                        return self.send_json({"L": server.height, "Z": server.bucket_size})

                    if self.path== "/trace" :
                        result=server.stats()
                        result["events"]= server.trace
                        return self.send_json(result)

                    if self.path=="/tracelen" :
                        return self.send_json({"n": len(server.trace)})

                    if self.path=="/stats" :
                        return self.send_json(server.stats())

                except (KeyError, IndexError, ValueError) as e:
                    return self. send_error_text(str(e))

            return self.send_error_text("Not found", 404)

    return Handler
if __name__=="__main__":
    parser= argparse.ArgumentParser(description="Path ORAM server (using https protocol)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("-L", type=int, default=10, help="tree height (2^L leaves)")
    parser.add_argument("--slot-size", type=int, default=4, help="slots per bucket")
    parser.add_argument("--cert", default="certs/cert.pem", help="server certificate (public)")
    parser.add_argument("--key", default="certs/key.pem", help="server private key")
    args= parser.parse_args()

    server= Server(args.L, args.slot_size)
    httpd= ThreadingHTTPServer((args.host, args.port), make_handler(server))

    # turn the plain socket into a tls socket
    context= ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version= ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(args.cert, args.key)
    except FileNotFoundError:
        print(f"certificate not found, create it first")
        sys.exit(1)
    httpd.socket= context.wrap_socket(httpd.socket, server_side=True)

    httpd.daemon_threads= True
    print(f"ORAM server on https://{args.host}:{args.port}  L={args.L} slot_size={args.slot_size} ({server.total_nodes} buckets)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass