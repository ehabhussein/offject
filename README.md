<pre>
file: offject_thumb_bin.py
"""injects Thumb instructions at a specific location in a binary"""

Usage:
rd@Wakanda $ hexdump -C foo.txt 
00000000  41 53 20 49 46 20 54 48  49 53 20 49 53 20 41 20  |AS IF THIS IS A |
00000010  42 49 4e 41 52 59 20 3a  29 0a                    |BINARY :).|
0000001a
rd@Wakanda $ ./offject.py -i foo.txt -o bar.txt
offject> mov r1,r1 
0946
offject> nop
094600bf
offject> write
Enter offset: 0xabc >0x10
Done!

rd@Wakanda $ hexdump -C bar.txt 
00000000  41 53 20 49 46 20 54 48  49 53 20 49 53 20 41 20  |AS IF THIS IS A |
00000010  09 46 00 bf 52 59 20 3a  29 0a                    |.F..RY :).|
0000001a
---------------------------------------------

</pre>
