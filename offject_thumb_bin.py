#!/usr/bin/python2
"""Injects Thumb instructions at a specified location in a binary (corterx-M0)"""
from keystone import *
import binascii
from shutil import copyfileobj
import argparse


if __name__ == '__main__':
    getopts = argparse.ArgumentParser()
    getopts.add_argument("-i",help="input file name",dest="infile",required=True)
    getopts.add_argument("-o",help="output file name",dest="outfile",required=True)
    getargs = getopts.parse_args()
    target = open(getargs.infile,'rb')
    outfile = open(getargs.outfile,'w+b')
    copyfileobj(target, outfile)
    opcodes = []
    opcs = None
    while True:
        x = raw_input("offject> ")
        if x.lower() == 'end':
            break
        elif len(x) == 0:
            continue
        elif x.lower() == 'write':
            offset = input("Enter offset: [0xabc]> ")
            outfile.seek(0)
            outfile.seek(offset)
            outfile.write(opcs)
            outfile.close()
            break
        else:
            try:
                for i in (Ks(KS_ARCH_ARM, KS_MODE_THUMB).asm(x))[0]:
                    opcodes.append("%02x" % i)
                print ''.join(opcodes)
                opcs = binascii.unhexlify(''.join(opcodes))
            except Exception as e:
                print(e)
    print "Done!"
