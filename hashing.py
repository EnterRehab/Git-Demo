import hashlib
import sys
import os

# Define the hashing algorithms to use
HASH_ALGOS = {
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
    'SHA224': hashlib.sha224,
    'SHA256': hashlib.sha256,
    'SHA384': hashlib.sha384,
    'SHA512': hashlib.sha512,
    'SHA3_256': hashlib.sha3_256,
    'SHA3_512': hashlib.sha3_512,
    'BLAKE2b': hashlib.blake2b,
    'BLAKE2s': hashlib.blake2s
}

def compute_hashes(file_path):
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return

    # Initialize hash objects
    hash_objs = {name: func() for name, func in HASH_ALGOS.items()}

    # Read file in chunks to handle large files
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for h in hash_objs.values():
                h.update(chunk)

    print(f"\nHash results for: {os.path.basename(file_path)}\n")
    for name, h in hash_objs.items():
        print(f"{name:10s}: {h.hexdigest()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python multi_hash.py <file_path>")
    else:
        compute_hashes(sys.argv[1])
