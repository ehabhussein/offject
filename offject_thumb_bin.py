#!/usr/bin/python2
"""injects Thumb instructions at a specific location in a binary"""

from keystone import *
from sys import argv
import binascii
from shutil import copyfileobj


if __name__ == '__main__':
    try:
        target = open(argv[1],'rb')
    except:
        pass
    try:
        outfile = open(argv[2],'w+b')
        copyfileobj(target, outfile)
    except:
        pass
    opcodes = []
    opcs = None
    while True:
        x = raw_input("offject> ")
        if x.lower() == 'end':
            break
        elif len(x) == 0:
            continue
        elif x.lower() == 'write':
            offset = input("Enter offset: 0xabc >")
            outfile.seek(0)
            outfile.seek(offset)
            outfile.write(opcs)
            outfile.close()
            break
        else:
            try:
                for i in (Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm(x, 0x00000000))[0]:
                    opcodes.append("%02x" % i)
                print ''.join(opcodes)
                opcs = binascii.unhexlify(''.join(opcodes))
            except Exception as e:
                print(e)
    print "Done!"
