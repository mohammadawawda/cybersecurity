import http.client
import json
import os
import socket
import ssl
from urllib.parse import urlparse


def enc_bucket(bucket):
    """
    bytes to hex strings so json can carry them, None stays None
    """
    list_of_hexStrings=[]
    for slot in bucket:
        list_of_hexStrings.append(slot.hex() if slot is not None else None)

    return list_of_hexStrings


def dec_bucket(bucket):
    """
    hex strings to bytes, a bucket that was never written (None) becomes []
    """
    if bucket is None:
        return []
    list_of_bytes=[]
    for slot in bucket:
        # fromhex belongs to bytes, not to str
        list_of_bytes.append(bytes.fromhex(slot) if slot is not None else None)
    return list_of_bytes
class ServerError(Exception):
    pass

class ClientRPC:
    def __init__(self,url, cerfile=None, timeout=60):
        self.url = url
        parsed= urlparse(url)
        self.host= parsed.hostname or "localhost"
        self.port= parsed.port or 443

        if cerfile is None:

            cerfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs", "cert.pem")

        self.cerfile = cerfile
        self.timeout = timeout
        self.conn = None

    def connection(self):
        #there's an active connection
        if self.conn is not None:
            return self.conn
        # tls trusts only or certificate and checks the hostname
        context=ssl.create_default_context(cafile=self.cerfile)
        #open https connectionm with tls handshake, bad certificate is raised here
        conn = http.client.HTTPSConnection(self.host, self.port,timeout=self.timeout,context=context)
        conn.connect()
        # make the connection on with tcp and no delay
        conn.sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)

        #keep the connection running for future calls
        self.conn = conn
        return conn

    def call(self,path, body=None):
        #get the body in json format
        data = json.dumps(body if body is not None else {}).encode()
        conn = self.connection()
        try:
            conn.request("POST", path, body=data, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            payload = response.read()
        except Exception:
            self.close()
            raise
        if response.status != 200:
            raise ServerError(f"server did not accept the request {path}: {response.status}: {payload.decode(errors='replace')}")
        return json.loads(payload) if payload else None

    def close(self):
        if self.conn is not None:
            self.conn.close()
        self.conn = None

    def read_path(self,leaf):
        """
            returns the buckets on the path from root to leaf  as bytes
        """
        reply = self.call("/read", {"leaf": leaf})
        decrypted_buckets=[]
        for bucket in reply["buckets"]:
            decrypted_buckets.append(dec_bucket(bucket))
        return decrypted_buckets

    def write_path(self,leaf,start,buckets):
        """
        overwrite the buckets on the path from root to leaf
        """
        encoded_buckets=[]
        for bucket in buckets:
            encoded_buckets.append(enc_bucket(bucket))

        self.call("/write",{"leaf": leaf,"from": start,"buckets": encoded_buckets})

    def reset(self, height, bucket_size):
        """
        empty the server tree and trace
        """
        self.call("/reset", {"L": height, "Z": bucket_size})

    def params(self):
        """
        returns the server's tree height and bucket size
        """
        return self.call("/params")

    def trace(self):
        """
        returns everything the server saw(the list of events and the counters))
        """
        return self.call("/trace")

    def trace_len(self):
        """
        returns the number of events in the server trace
        """
        return self.call("/tracelen")["n"]

    def stats(self):
        """
        returns the server counters only
        """
        return self.call("/stats")