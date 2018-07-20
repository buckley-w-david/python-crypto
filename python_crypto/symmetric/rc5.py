import math

def _rotate_left(val, r_bits, max_bits):
    v1 = (val << r_bits%max_bits) & (2**max_bits-1)
    v2 = ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
    return v1 | v2

def _rotate_right(val, r_bits, max_bits):
    v1 = ((val & (2**max_bits-1)) >> r_bits%max_bits)
    v2 = (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

    return v1 | v2

def _expand_key(key, wordsize, rounds):
    #Pads key so that it is aligned with the word size, then splits it into words
    def _align_key(key, align_val):
        while len(key) % (align_val):
            key += b'\x00' #Add 0 bytes until the key length is aligned to the block size

        L = []
        for i in range(0, len(key), align_val):
            L.append(int.from_bytes(key[i:i+align_val], byteorder='little'))

        return L

    #generation function of the constants for the extend step
    def _const(w):
        if w == 16:
            return (0xB7E1, 0x9E37) # Returns the value of P and Q
        elif w == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif w == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    #Generate pseudo-random list S
    def _extend_key(w, r):
        P, Q = _const(w)
        S = [P]
        t = 2*(r+1)
        for i in range(1, t):
            S.append((S[i-1]+Q) % 2**w)

        return S

    def _mix(L, S, r, w, c):
        t = 2*(r+1)
        m = max(c, t)
        A = B = i = j = 0

        for k in range(3*m):
            A = S[i] = _rotate_left(S[i]+A+B, 3, w)
            B = L[j] = _rotate_left(L[j]+A+B, A+B, w)

            i = (i+1) % t
            j = (j+1) % c

        return S

    aligned = _align_key(key, wordsize//8)
    extended = _extend_key(wordsize, rounds)

    S = _mix(aligned, extended, rounds, wordsize, len(aligned))

    return S

def _encrypt_block(data, expanded_key, blocksize, rounds):
    w = blocksize//2
    b = blocksize//8
    mod = 2**w

    A = int.from_bytes(data[:b//2], byteorder='little')
    B = int.from_bytes(data[b//2:], byteorder='little')

    A = (A+expanded_key[0]) % mod
    B = (B+expanded_key[1]) % mod

    for i in range(1, rounds+1):
        A = (_rotate_left((A^B), B, w) + expanded_key[2 * i]) % mod
        B = (_rotate_left((A^B), A, w) + expanded_key[2 * i + 1]) % mod

    res = A.to_bytes(b//2, byteorder='little') + B.to_bytes(b//2, byteorder='little')
    return res

def _decrypt_block(data, expanded_key, blocksize, rounds):
    w = blocksize//2
    b = blocksize//8
    mod = 2**w

    A = int.from_bytes(data[:b//2], byteorder='little')
    B = int.from_bytes(data[b//2:], byteorder='little')

    for i in range(rounds, 0, -1):
        B = _rotate_right(B-expanded_key[2*i+1], A, w)^A
        A = _rotate_right((A-expanded_key[2*i]), B, w)^B

    B = (B - expanded_key[1]) % mod
    A = (A - expanded_key[0]) % mod

    res = A.to_bytes(b//2, byteorder='little') + B.to_bytes(b//2, byteorder='little')
    return res

def encrypt_file(infile, outfile, key, blocksize, rounds):
    w = blocksize//2
    b = blocksize//8

    expanded_key = _expand_key(key, w, rounds)

    chunk = infile.read(b)
    while chunk:
        chunk = chunk.ljust(b, b'\x00') #padding with 0 bytes if not large enough
        encrypted_chunk = _encrypt_block(chunk, expanded_key, blocksize, rounds)
        outfile.write(encrypted_chunk)

        chunk = infile.read(b) #Read in blocksize number of bytes

def decrypt_file(infile, outfile, key, blocksize, rounds):
    w = blocksize//2
    b = blocksize//8

    expanded_key = _expand_key(key, w, rounds)

    chunk = infile.read(b)
    while chunk:
        decrypted_chunk = _decrypt_block(chunk, expanded_key, blocksize, rounds)
        chunk = infile.read(b) #Read in blocksize number of bytes
        if not chunk:
            decrypted_chunk = decrypted_chunk.rstrip(b'\x00')

        outfile.write(decrypted_chunk)
