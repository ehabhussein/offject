#!/usr/bin/python3

from sys import argv
from os import mkdir
import time
from os import environ

y,m,d = map(int,list(time.gmtime())[0:3]) 

if __name__ == '__main__':
	mydir = "%s/projects/%s-%d-%d-%d"%(environ['HOME'],argv[1],d,m,y) 
	mkdir(mydir)
	for i in ['credentials','images','docs','finds','scratchpad','todo','exploits','reversing','web','code-review','network','scope','burpsaves','reports']:
		mkdir("%s/%s"%(mydir,i)) 	
	print("project created!")
