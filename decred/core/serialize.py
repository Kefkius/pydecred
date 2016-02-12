import blake_hash
import hashlib

def DecredHash(msg):
    return blake_hash.getPoWHash(msg)

def Hash160(msg):
    """RIPEMD_160(BLAKE256(msg))"""
    h = hashlib.new('ripemd160')
    h.update(DecredHash(msg))
    return h.digest()
