

intro = """
    blake.py
    version 4
    
    BLAKE is a SHA3 round-3 finalist designed and submitted by 
    Jean-Philippe Aumasson et al.
    
    At the core of BLAKE is a ChaCha-like mixer, very similar 
    to that found in the stream cipher, ChaCha8.  Besides being 
    a very good mixer, ChaCha is fast.  
    
    References:
      http://www.131002.net/blake/
      http://csrc.nist.gov/groups/ST/hash/sha-3/index.html
      http://en.wikipedia.org/wiki/BLAKE_(hash_function)
    
    This implementation assumes all data is in increments of 
    whole bytes.  (The formal definition of BLAKE allows for 
    hashing individual bits.)  Note too that this implementation 
    does include the round-3 tweaks where the number of rounds 
    was increased to 14/16 from 10/14.
    
    This version can be imported into both Python2 and Python3 
    programs.

    Here are some comparative run times for different versions 
    of Python:

        64-bit:
            2.6         6.28s
            2.7         6.34s
            3.2         7.62s
            pypy (2.7)  2.08s

        32-bit:
            2.7        13.65s
            3.2        12.57s

    Another test on a 2.0GHz Core 2 Duo of 10,000 iterations of 
    BLAKE-256 on a short message produced a time of 5.7 seconds.  
    Not bad, but if raw speed is what you want, look to the t
    he C version.  It is 40x faster and did the same thing in 
    0.13 seconds.
    
        Copyright (c) 2009-2012 by Larry Bugbee, Kent, WA
        ALL RIGHTS RESERVED.
        
        blake.py IS EXPERIMENTAL SOFTWARE FOR EDUCATIONAL
        PURPOSES ONLY.  IT IS MADE AVAILABLE "AS-IS" WITHOUT 
        WARRANTY OR GUARANTEE OF ANY KIND.  USE SIGNIFIES 
        ACCEPTANCE OF ALL RISK.  

    To make your learning and experimentation less cumbersome, 
    blake.py is free for any use.      
    
    Enjoy,
        
    Larry Bugbee
    March 2011
    rev May 2011 - fixed Python version check (tx JP)
    rev Apr 2012 - fixed an out-of-order bit set in final()
                 - moved self-test to a separate test pgm
                 - this now works with Python2 and Python3
    
"""

import struct

try:
    import psyco    # works on some 32-bit Python2 versions only
    have_psyco = True
    print('psyco enabled')
except:
    have_psyco = False
    
#---------------------------------------------------------------

class BLAKE(object):

    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # initial values, constants and padding
    
    # IVx for BLAKE-x
    
    IV64 = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]
    
    IV48 = [
        0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
        0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511,
        0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
    ]
    
    # note: the values here are the same as the high-order 
    #       half-words of IV64
    IV32 = [
        0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C,
        0x1F83D9AB, 0x5BE0CD19,
    ]
    
    # note: the values here are the same as the low-order 
    #       half-words of IV48
    IV28 = [
        0xC1059ED8, 0x367CD507,
        0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511,
        0x64F98FA7, 0xBEFA4FA4,
    ]
    
    # constants for BLAKE-64 and BLAKE-48
    C64 = [
        0x243F6A8885A308D3, 0x13198A2E03707344,
        0xA4093822299F31D0, 0x082EFA98EC4E6C89,
        0x452821E638D01377, 0xBE5466CF34E90C6C,
        0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
        0x9216D5D98979FB1B, 0xD1310BA698DFB5AC,
        0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
        0xBA7C9045F12C7F99, 0x24A19947B3916CF7,
        0x0801F2E2858EFC16, 0x636920D871574E69,
    ]
    
    # constants for BLAKE-32 and BLAKE-28
    # note: concatenate and the values are the same as the values 
    #       for the 1st half of C64
    C32 = [
        0x243F6A88, 0x85A308D3,
        0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0,
        0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377,
        0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD,
        0x3F84D5B5, 0xB5470917,
    ]
    
    # the 10 permutations of:0,...15}
    SIGMA = [
        [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
        [14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
        [11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
        [ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
        [ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
        [ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
        [12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
        [13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
        [ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
        [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15],
        [14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3],
        [11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4],
        [ 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8],
        [ 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13],
        [ 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9],
        [12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11],
        [13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10],
        [ 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0],
    ]
        
    MASK32BITS = 0xFFFFFFFF
    MASK64BITS = 0xFFFFFFFFFFFFFFFF
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def __init__(self, hashbitlen):
        """
          load the hashSate structure (copy hashbitlen...)
          hashbitlen: length of the hash output
        """
        if hashbitlen not in [224, 256, 384, 512]:
            raise Exception('hash length not 224, 256, 384 or 512')
        
        self.hashbitlen = hashbitlen
        self.h     = [0]*8  # current chain value (initialized to the IV)
        self.t     = 0      # number of *BITS* hashed so far
        self.cache = b''    # cached leftover data not yet compressed
        self.salt  = [0]*4  # salt (null by default)
        self.init  = 1      # set to 2 by update and 3 by final
        self.nullt = 0      # Boolean value for special case \ell_i=0
        
        # The algorithm is the same for both the 32- and 64- versions 
        # of BLAKE.  The difference is in word size (4 vs 8 bytes), 
        # blocksize (64 vs 128 bytes), number of rounds (14 vs 16)
        # and a few very specific constants.
        if (hashbitlen == 224) or (hashbitlen == 256):
            # setup for 32-bit words and 64-bit block
            self.byte2int  = self._fourByte2int
            self.int2byte  = self._int2fourByte
            self.MASK      = self.MASK32BITS
            self.WORDBYTES = 4
            self.WORDBITS  = 32
            self.BLKBYTES  = 64
            self.BLKBITS   = 512
            # self.ROUNDS    = 14   # was 10 before round 3
            self.ROUNDS    = 8      # BLAKE 8 for blakecoin
            self.cxx  = self.C32
            self.rot1 = 16          # num bits to shift in G
            self.rot2 = 12          # num bits to shift in G 
            self.rot3 = 8           # num bits to shift in G 
            self.rot4 = 7           # num bits to shift in G
            self.mul  = 0   # for 32-bit words, 32<<self.mul where self.mul = 0
            
            # 224- and 256-bit versions (32-bit words)
            if hashbitlen == 224:
                self.h = self.IV28[:]
            else:
                self.h = self.IV32[:]
    
        elif (hashbitlen == 384) or (hashbitlen == 512):
            # setup for 64-bit words and 128-bit block
            self.byte2int  = self._eightByte2int
            self.int2byte  = self._int2eightByte
            self.MASK      = self.MASK64BITS
            self.WORDBYTES = 8
            self.WORDBITS  = 64
            self.BLKBYTES  = 128
            self.BLKBITS   = 1024
            self.ROUNDS    = 16     # was 14 before round 3
            self.cxx  = self.C64
            self.rot1 = 32          # num bits to shift in G
            self.rot2 = 25          # num bits to shift in G
            self.rot3 = 16          # num bits to shift in G
            self.rot4 = 11          # num bits to shift in G
            self.mul  = 1   # for 64-bit words, 32<<self.mul where self.mul = 1
            
            # 384- and 512-bit versions (64-bit words)
            if hashbitlen == 384:
                self.h = self.IV48[:]
            else:
                self.h = self.IV64[:]
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def _compress(self, block):
        byte2int = self.byte2int
        mul      = self.mul       # de-reference these for  ...speed?  ;-)
        cxx      = self.cxx
        rot1     = self.rot1
        rot2     = self.rot2
        rot3     = self.rot3
        rot4     = self.rot4
        MASK     = self.MASK
        WORDBITS = self.WORDBITS
        SIGMA    = self.SIGMA
        
        # get message       (<<2 is the same as *4 but faster)
        m = [byte2int(block[i<<2<<mul:(i<<2<<mul)+(4<<mul)]) for i in range(16)]        
        
        # initialization
        v = [0]*16
        v[ 0: 8] = [self.h[i] for i in range(8)]
        v[ 8:16] = [self.cxx[i] for i in range(8)]
        v[ 8:12] = [v[8+i] ^ self.salt[i] for i in range(4)]
        if self.nullt == 0:        #    (i>>1 is the same as i/2 but faster)
            v[12] = v[12] ^ (self.t & MASK)
            v[13] = v[13] ^ (self.t & MASK)
            v[14] = v[14] ^ (self.t >> self.WORDBITS)
            v[15] = v[15] ^ (self.t >> self.WORDBITS)
        
        # - - - - - - - - - - - - - - - - -
        # ready?  let's ChaCha!!!
        
        def G(a, b, c, d, i):
            va = v[a]   # it's faster to deref and reref later
            vb = v[b]
            vc = v[c]
            vd = v[d]
            
            sri  = SIGMA[round][i]
            sri1 = SIGMA[round][i+1]
            
            va = ((va + vb) + (m[sri] ^ cxx[sri1]) ) & MASK
            x  =  vd ^ va
            vd = (x >> rot1) | ((x << (WORDBITS-rot1)) & MASK)
            vc = (vc + vd) & MASK
            x  =  vb ^ vc
            vb = (x >> rot2) | ((x << (WORDBITS-rot2)) & MASK)
            
            va = ((va + vb) + (m[sri1] ^ cxx[sri]) ) & MASK
            x  =  vd ^ va
            vd = (x >> rot3) | ((x << (WORDBITS-rot3)) & MASK)
            vc = (vc + vd) & MASK
            x  =  vb ^ vc
            vb = (x >> rot4) | ((x << (WORDBITS-rot4)) & MASK)
            
            v[a] = va
            v[b] = vb
            v[c] = vc
            v[d] = vd
            
        for round in range(self.ROUNDS):
            # column step
            G( 0, 4, 8,12, 0)
            G( 1, 5, 9,13, 2)
            G( 2, 6,10,14, 4)
            G( 3, 7,11,15, 6)
            # diagonal step
            G( 0, 5,10,15, 8)
            G( 1, 6,11,12,10)
            G( 2, 7, 8,13,12)
            G( 3, 4, 9,14,14)
        
        # - - - - - - - - - - - - - - - - -
        
        # save current hash value   (use i&0x3 to get 0,1,2,3,0,1,2,3)
        self.h = [self.h[i]^v[i]^v[i+8]^self.salt[i&0x3] 
                                                for i in range(8)]
    #    print 'self.h', [num2hex(h) for h in self.h]
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def addsalt(self, salt):
        """ adds a salt to the hash function (OPTIONAL)
            should be called AFTER Init, and BEFORE update
            salt:  a bytestring, length determined by hashbitlen.
                   if not of sufficient length, the bytestring 
                   will be assumed to be a big endian number and 
                   prefixed with an appropriate number of null 
                   bytes, and if too large, only the low order 
                   bytes will be used.
            
              if hashbitlen=224 or 256, then salt will be 16 bytes
              if hashbitlen=384 or 512, then salt will be 32 bytes
        """
        # fail if addsalt() was not called at the right time
        if self.init != 1:
            raise Exception('addsalt() not called after init() and before update()')
        # salt size is to be 4x word size
        saltsize = self.WORDBYTES * 4
        # if too short, prefix with null bytes.  if too long, 
        # truncate high order bytes
        if len(salt) < saltsize:
            salt = (chr(0)*(saltsize-len(salt)) + salt)
        else:
            salt = salt[-saltsize:]
        # prep the salt array
        self.salt[0] = self.byte2int(salt[            : 4<<self.mul])
        self.salt[1] = self.byte2int(salt[ 4<<self.mul: 8<<self.mul])
        self.salt[2] = self.byte2int(salt[ 8<<self.mul:12<<self.mul])
        self.salt[3] = self.byte2int(salt[12<<self.mul:            ])
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def update(self, data):
        """ update the state with new data, storing excess data 
            as necessary.  may be called multiple times and if a 
            call sends less than a full block in size, the leftover 
            is cached and will be consumed in the next call 
            data:  data to be hashed (bytestring)
        """
        self.init = 2
        
        BLKBYTES = self.BLKBYTES   # de-referenced for improved readability
        BLKBITS  = self.BLKBITS
        
        datalen = len(data)
        if not datalen:  return
    
        left = len(self.cache)
        fill = BLKBYTES - left
        
        # if any cached data and any added new data will fill a 
        # full block, fill and compress
        if left and datalen >= fill:
            self.cache = self.cache + data[:fill]
            self.t += BLKBITS           # update counter
            self._compress(self.cache)
            self.cache = b''
            data = data[fill:]
            datalen -= fill
    
        # compress new data until not enough for a full block
        while datalen >= BLKBYTES:        
            self.t += BLKBITS           # update counter
            self._compress(data[:BLKBYTES])
            data = data[BLKBYTES:]
            datalen -= BLKBYTES
        
        # cache all leftover bytes until next call to update()
        if datalen > 0:
            self.cache = self.cache + data[:datalen]
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def final(self, data=''):
        """ finalize the hash -- pad and hash remaining data
            returns hashval, the digest
        """
        ZZ = b'\x00'
        ZO = b'\x01'
        OZ = b'\x80'
        OO = b'\x81'
        PADDING = OZ + ZZ*128   # pre-formatted padding data    
    
        if data:
            self.update(data)
            
        # copy nb. bits hash in total as a 64-bit BE word
        # copy nb. bits hash in total as a 128-bit BE word
        tt = self.t + (len(self.cache) << 3)
        if self.BLKBYTES == 64:
            msglen = self._int2eightByte(tt)
        else:
            low  = tt & self.MASK
            high = tt >> self.WORDBITS
            msglen = self._int2eightByte(high) + self._int2eightByte(low)
        
        # size of block without the words at the end that count 
        # the number of bits, 55 or 111.
        # Note: (((self.WORDBITS/8)*2)+1) equals ((self.WORDBITS>>2)+1)
        sizewithout = self.BLKBYTES -  ((self.WORDBITS>>2)+1)
    
        if len(self.cache) == sizewithout:
            # special case of one padding byte
            self.t -= 8
            if self.hashbitlen in [224, 384]:
                self.update(OZ)
            else:
                self.update(OO)
        else:
            if len(self.cache) < sizewithout:
                # enough space to fill the block
                # use t=0 if no remaining data
                if len(self.cache) == 0:
                    self.nullt=1
                self.t -= (sizewithout - len(self.cache)) << 3
                self.update(PADDING[:sizewithout - len(self.cache)])
            else: 
                # NOT enough space, need 2 compressions
                #   ...add marker, pad with nulls and compress
                self.t -= (self.BLKBYTES - len(self.cache)) << 3 
                self.update(PADDING[:self.BLKBYTES - len(self.cache)])
                #   ...now pad w/nulls leaving space for marker & bit count
                self.t -= (sizewithout+1) << 3
                self.update(PADDING[1:sizewithout+1]) # pad with zeroes
                
                self.nullt = 1 # raise flag to set t=0 at the next _compress
            
            # append a marker byte
            if self.hashbitlen in [224, 384]:
                self.update(ZZ)
            else:
                self.update(ZO)
            self.t -= 8
        
        # append the number of bits (long long)
        self.t -= self.BLKBYTES
        self.update(msglen)
    
        hashval = []
        if self.BLKBYTES == 64:
            for h in self.h:
                hashval.append(self._int2fourByte(h))
        else:
            for h in self.h:
                hashval.append(self._int2eightByte(h))
        return b''.join(hashval)[:self.hashbitlen >> 3]
    
    digest = final      # may use digest() as a synonym for final()
    
    def midstate(self, data=''):
    
        if data:
            self.update(data)

        hashval = []
        if self.BLKBYTES == 64:
            for h in self.h:
                hashval.append(self._int2fourByte(h))
        else:
            for h in self.h:
                hashval.append(self._int2eightByte(h))
        return b''.join(hashval)[:self.hashbitlen >> 3]

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # utility functions
    
    def _fourByte2int(self, bytestr):      # see also long2byt() below
        """ convert a 4-byte string to an int (long) """
        return struct.unpack('!L', bytestr)[0]
    
    def _eightByte2int(self, bytestr):
        """ convert a 8-byte string to an int (long long) """
        return struct.unpack('!Q', bytestr)[0]
    
    def _int2fourByte(self, x):            # see also long2byt() below
        """ convert a number to a 4-byte string, high order 
            truncation possible (in Python x could be a BIGNUM)
        """
        return struct.pack('!L', x)
    
    def _int2eightByte(self, x):
        """ convert a number to a 8-byte string, high order 
            truncation possible (in Python x could be a BIGNUM)
        """
        return struct.pack('!Q', x)
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    if have_psyco:
        _compress = psyco.proxy(self._compress)


#---------------------------------------------------------------
#---------------------------------------------------------------
#---------------------------------------------------------------
