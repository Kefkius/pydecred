import blake_hash

def DecredHash(msg):
    return blake_hash.getPoWHash(msg)
