import hashlib, binascii

from enum import Enum, auto
from Crypto.Hash import keccak

class Hash(Enum):
    SHA_224 = auto()
    SHA_256 = auto()
    SHA3_224 = auto()
    SHA3_384 = auto()
    KECCAK_384 = auto()

    def keccak(self, mb, digest_bits):
        keccak_hash = keccak.new(digest_bits=digest_bits)
        keccak_hash.update(mb)
        return keccak_hash

    def create(self, m):
        mb = m.encode('utf-8')
        hash_fn = {
            'SHA_224': lambda sb: hashlib.sha224(sb).digest(),
            'SHA_256': lambda sb: hashlib.sha256(sb).digest(),
            'SHA3_224': lambda sb: hashlib.sha3_224(sb).digest(),
            'SHA3_384': lambda sb: hashlib.sha3_384(sb).digest(),
            'KECCAK_384': lambda sb: self.keccak(sb, 384).digest()
        }.get(self.name)
        return binascii.hexlify(hash_fn(mb))

# Compute SHA-256
def test_sha_256():
    hashed = b'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    assert Hash.SHA_256.create("hello") == hashed

# Compute SHA-224
def test_sha_224():
    hashed = b'ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193'
    assert Hash.SHA_224.create("hello") == hashed

# Compute SHA3-224
def test_sha3_224():
    hashed = b'b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81'
    assert Hash.SHA3_224.create("hello") == hashed

# Compute SHA3-384
def test_sha3_384():
    hashed = b'720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887'
    assert Hash.SHA3_384.create("hello") == hashed

# Compute KECCAK-384
def test_keccak_384():
    hashed = b'dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb4cd8e9c703b8f43e7277b59a5cd402175'
    assert Hash.KECCAK_384.create("hello") == hashed

