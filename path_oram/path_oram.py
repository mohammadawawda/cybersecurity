"""
Non-recursive Path ORAM
Includes AES-GCM encryption and integrity verification.
"""

import os
import math
import random
import hashlib
import struct
from Crypto.Cipher import AES


DUMMY_BLOCK_ID = -1  # Sentinel value for dummy/empty blocks


def pad_data(data: bytes, block_size: int) -> bytes:
    """Pad data to exactly block_size bytes."""
    if len(data) > block_size:
        raise ValueError(f"Data size {len(data)} exceeds block size {block_size}")
    return data + b'\x00' * (block_size - len(data))


def serialize_block(block_id: int, data: bytes) -> bytes:
    """Serialize a block: 4 byte ID + data."""
    # we use the struct library to convert from integers to bytes
    return struct.pack('>i', block_id) + data


def deserialize_block(raw: bytes) -> tuple:
    """Deserialize a block into (block_id, data)."""
    block_id = struct.unpack('>i', raw[:4])[0]
    data = raw[4:]
    return block_id, data



class Server:
    """
    stores encrypted data in a binary tree
    each node is a bucket holding Z encrypted blocks.
    The tree is stored as an array.
    """

    def __init__(self, num_leaves: int, bucket_size: int = 4):
        """
        Initialize the server with an empty tree.
        
        Args:
            num_leaves: Number of leaves in the tree, it must be a power of 2
            bucket_size: Number of slots per bucket, Default = 4.
        """
        self.num_leaves = num_leaves
        self.bucket_size = bucket_size
        # number of nodes in a complete binary tree
        self.total_nodes = 2 * num_leaves
        # tree[i] = list of the encrypted strings (Z ciphertexts)
        # Initialize with None
        self.tree = [None] * self.total_nodes

    def read_bucket(self, node_index: int) -> list:
        """Read a single bucket (list of Z ciphertexts) from the tree."""
        if node_index < 1 or node_index >= self.total_nodes:
            raise IndexError(f"Node index {node_index} out of range")
        return self.tree[node_index]

    def write_bucket(self, node_index: int, bucket: list):
        """Write a bucket (list of Z ciphertexts) to the tree."""
        if node_index < 1 or node_index >= self.total_nodes:
            raise IndexError(f"Node index {node_index} out of range")
        self.tree[node_index] = bucket

    def get_path(self, leaf: int) -> list:
        """
        Get the list of node indices on the path from the given leaf to the root.
        Returns indices from leaf to root.

        """
        node = leaf
        path = []
        while node >= 1:
            path.append(node)
            node = node // 2
        return path  # leaf to root order

    def read_path(self, leaf: int) -> list:
        """
        Read all buckets along the path from leaf to root.
        
        Returns:
            List of (node_index, bucket) from leaf to root.
        """
        path_indices = self.get_path(leaf)
        result = []
        for idx in path_indices:
            result.append((idx, self.read_bucket(idx)))
        return result

    def write_path(self, path_data: list):
        """
        Write buckets back along a path.
        
        Args:
            path_data: List of (node_index, bucket).
        """
        for idx, bucket in path_data:
            self.write_bucket(idx, bucket)


class Client:
    """
    Path ORAM client that hides access patterns from the server.
    
    The client holds:
      encryption key
      position map that maps block_id to leaf index
      version hash map that maps block_id to SHA-256(plaintext data)
      stash: overflow blocks that couldn't fit in the tree
    """

    def __init__(self, server: Server, num_blocks: int, block_size: int = 4096):
        """
        Initialize the client and fill the server tree with encrypted dummies.
        
        Args:
            server: The Server instance to use.
            num_blocks: Number of data blocks (N) the ORAM supports.
            block_size: Size of each data block in bytes. Default = 4096.
        """
        self.server = server
        self.num_blocks = num_blocks
        self.block_size = block_size
        self.bucket_size = server.bucket_size

        # AES-256 key for encryption
        self.key = os.urandom(32)

        # Position map mapping block_id to leaf index in the tree
        self.position_map = {}

        # Version hash map for integrity checking: block_id to SHA-256(data)
        self.version_hash = {}

        # Stash: list of (block_id, data_bytes)
        self.stash = []

        # Initialize the entire server tree with encrypted dummy blocks
        self._initialize_tree(server)

    def _initialize_tree(self, server: Server):
        """Fill every bucket in the server tree with encrypted dummy blocks."""
        for node_idx in range(1, server.total_nodes):
            bucket = []
            for _ in range(self.bucket_size):
                dummy_plain = serialize_block(DUMMY_BLOCK_ID, pad_data(b'', self.block_size))
                bucket.append(self._encrypt(dummy_plain))
            server.write_bucket(node_idx, bucket)



    def _encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with AES using a fresh random nonce
        Returns: nonce (12 bytes) + tag (16 bytes) + ciphertext
        """
        nonce = os.urandom(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    def _decrypt(self, encrypted: bytes) -> bytes:
        """
        Decrypt AES
        Input: nonce (12 bytes) + tag (16 bytes) + ciphertext
        Raises ValueError if authentication fails
        """
        nonce = encrypted[:12]
        tag = encrypted[12:28]
        ciphertext = encrypted[28:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext



    def _random_leaf(self) -> int:
        """Return a random leaf index in the server's tree."""
        return random.randint(self.server.num_leaves, 2 * self.server.num_leaves - 1)

    def _get_path_indices(self, leaf: int) -> list:
        """Get node indices from leaf to root."""
        return self.server.get_path(leaf)

    def _is_on_path(self, node_index: int, leaf: int) -> bool:
        """
        Check if node_index lies on the path from root to the given leaf.
        A node is on the path to a leaf if, when we walk from the leaf to
        the root, we pass through that node
        """
        current = leaf
        while current >= 1:
            if current == node_index:
                return True
            current = current // 2
        return False

    def _compute_hash(self, data: bytes) -> bytes:
        """Compute SHA-256 hash of data to check integrity """
        return hashlib.sha256(data).digest()



    def _access(self, server: Server, op_type: str, block_id: int, new_data: bytes = None):
        """
        Core Path ORAM access operation. Every operation follows the same
        pattern to preserve obliviousness.

        Args:
            server: The Server instance.
            op_type: "read", "write", or "delete".
            block_id: The ID of the block to access.
            new_data: The new data (for "write" operations). Must be <= block_size bytes.
        
        Returns:
            The block data (bytes) for "read", or None.
        """
        # Step 1: Look up or assign the leaf for this block
        if block_id in self.position_map:
            leaf = self.position_map[block_id]
        else:
            # Block doesn't exist yet, assign a random leaf
            leaf = self._random_leaf()
            self.position_map[block_id] = leaf

        # Step 2: Reassign to a new random leaf immediately
        new_leaf = self._random_leaf()
        self.position_map[block_id] = new_leaf

        # Step 3: Read the entire path from leaf to root
        path = server.read_path(leaf)

        # Decrypt all blocks on the path and move real blocks into the stash
        for node_idx, bucket in path:
            for encrypted_block in bucket:
                try:
                    plaintext = self._decrypt(encrypted_block)
                    bid, data = deserialize_block(plaintext)
                    if bid != DUMMY_BLOCK_ID:
                        # Only add if not already in stash (avoid duplicates)
                        if not any(s[0] == bid for s in self.stash):
                            self.stash.append((bid, data))
                except (ValueError, Exception):
                    # Decryption/authentication failed , tampering detected
                    raise RuntimeError(f"Integrity check failed: bucket at node may be corrupted")

        # Step 4: Perform the requested operation on the stash
        result = None

        if op_type == "read":
            # Find the block in the stash
            for bid, data in self.stash:
                if bid == block_id:
                    # Verify integrity against the padded data (what we stored)
                    if block_id in self.version_hash:
                        if self._compute_hash(data) != self.version_hash[block_id]:
                            raise RuntimeError(f"Integrity violation: block {block_id} data mismatch")
                    result = data.rstrip(b'\x00')  # Strip padding for return
                    break

        elif op_type == "write":
            padded_data = pad_data(new_data, self.block_size)
            # Remove old version from stash if it exists
            self.stash = [(bid, d) for bid, d in self.stash if bid != block_id]
            # Add updated block to stash
            self.stash.append((block_id, padded_data))
            # Update version hash — hash the padded data for consistency
            self.version_hash[block_id] = self._compute_hash(padded_data)
            result = None

        elif op_type == "delete":
            # Remove from stash
            self.stash = [(bid, d) for bid, d in self.stash if bid != block_id]
            # Remove from position map and version hash
            if block_id in self.position_map:
                del self.position_map[block_id]
            if block_id in self.version_hash:
                del self.version_hash[block_id]
            result = None

        # Step 5: Write the path back — evict blocks from stash into the tree
        # Process from leaf to root to push blocks as deep as possible
        path_indices = [node_idx for node_idx, _ in path]  # Already leaf-to-root

        write_back = []
        for node_idx in path_indices:
            bucket = []
            # Greedily fill this bucket with compatible blocks from the stash
            remaining_stash = []
            for bid, data in self.stash:
                if len(bucket) < self.bucket_size and bid in self.position_map:
                    # Check if this block's assigned leaf is compatible with this node
                    if self._is_on_path(node_idx, self.position_map[bid]):
                        bucket.append((bid, data))
                    else:
                        remaining_stash.append((bid, data))
                else:
                    remaining_stash.append((bid, data))
            self.stash = remaining_stash

            # Pad bucket with dummy blocks up to Z
            while len(bucket) < self.bucket_size:
                dummy_data = pad_data(b'', self.block_size)
                bucket.append((DUMMY_BLOCK_ID, dummy_data))

            # Encrypt every block with a fresh nonce
            encrypted_bucket = []
            for bid, data in bucket:
                plaintext = serialize_block(bid, data)
                encrypted_bucket.append(self._encrypt(plaintext))

            write_back.append((node_idx, encrypted_bucket))

        # Write the encrypted path back to the server
        server.write_path(write_back)

        return result


    def store_data(self, server: Server, block_id: int, data: bytes):
        """
        Store data associated with an ID on the server.
        
        Args:
            server: The Server instance.
            block_id: Integer ID for the data block.
            data: Byte array of data to store (must be <= block_size).
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._access(server, "write", block_id, data)

    def retrieve_data(self, server: Server, block_id: int) -> bytes:
        """
        Retrieve data associated with an ID from the server.
        
        Args:
            server: The Server instance.
            block_id: Integer ID for the data block.
        
        Returns:
            The data as bytes, or None if the block doesn't exist.
        """
        return self._access(server, "read", block_id)

    def delete_data(self, server: Server, block_id: int):
        """
        Delete data associated with an ID from the server.
        
        Args:
            server: The Server instance.
            block_id: Integer ID for the data block.
        """
        self._access(server, "delete", block_id)




def create_oram(num_blocks: int, block_size: int = 4096, bucket_size: int = 4):
    """
    Create a Path ORAM instance with the given parameters.
    
    Args:
        num_blocks: Number of data blocks (N) to support.
        block_size: Size of each data block in bytes (B).
        bucket_size: Slots per bucket (Z). Default = 4.
    
    Returns:
        (client, server) tuple.
    """
    # Number of leaves must be at least N, rounded up to next power of 2
    num_leaves = 1
    while num_leaves < num_blocks:
        num_leaves *= 2

    server = Server(num_leaves, bucket_size)
    client = Client(server, num_blocks, block_size)
    return client, server



