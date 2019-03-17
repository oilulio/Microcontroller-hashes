#!/usr/bin/env python3
from socket import *
import datetime
import hashlib

port=51000

""" Utility routine to test hashes broadcast over the network

Use case is testing microcontroller generating hashes

Listens for UDP packets on given port

Packets begin with 4 char id, "MD5=","SHA1" ...
then bigendian 16 bit length
then bigendian 16 bit LFSR state
then 32 bytes of hash/digest (ignore tail if longer than specified, e.g. MD5
  uses 16)

This allows the definition of a hash input of the next 'length' bytes
output from the LFSR

The provided hash is then compared with the locally calculated one.
Tallies are kept of successes and total hashes individually for each type

Note - UDP based so some packets may be lost

"""
MD5=0
SHA1=1
SHA256=2
RIP160=3
TOTAL=0
PASSED=1
#                     No measures          No Algs
results=[[0 for x in range(2)] for y in range(4)]
total=0
count=0

s=socket(AF_INET, SOCK_DGRAM)
s.bind(('',port))

while (True):
  data=s.recvfrom(1024)
  msg=data[0] 
  if (msg[0:4].decode(encoding="ISO-8859-1")=="MD5="):
    m=hashlib.md5()
    toproc=MD5
  elif (msg[0:4].decode(encoding="ISO-8859-1")=="SHA1"):
    m=hashlib.sha1()
    toproc=SHA1
  elif (msg[0:4].decode(encoding="ISO-8859-1")=="S256"):
    m=hashlib.sha256()
    toproc=SHA256
  elif (msg[0:4].decode(encoding="ISO-8859-1")=="R160"):
    m=hashlib.ripemd160()
    toproc=RIP160
  elif (msg[0:4].decode(encoding="ISO-8859-1")=="BUF="):
    for i in range(4,len(msg),1):
      print('{:02x} '.format(msg[i]),end=''),
      if ((i-3)%16==0):
        print()
    print()
    continue  
  else:    
    print("Error , unexpected data:",data[0])

  length=msg[4]*256+msg[5]
  lfsr=msg[6]*256+msg[7]

  tohash=""
  for i in range(length):
    mybyte=0
    for j in range(8):
      mybyte<<=1
      mybyte|=(lfsr&1)
      lfsr=lfsr>>1
      if ((mybyte&1)!=0):
        lfsr^=0xB400
      
    tohash+=chr(mybyte)
    
  m.update(tohash.encode(encoding="ISO-8859-1"))
  hsh=m.digest()
  passed=True
  for i in range(len(hsh)):
    if (hsh[i]!=msg[i+8]):
      passed=False
    if (False):
      print(hex(hsh[i]),hex(msg[i+8]),passed,length,lfsr)

  total+=1
  results[toproc][TOTAL]+=1
  if (passed):
    results[toproc][PASSED]+=1
      
  if ((total%100)==0):
    print(datetime.datetime.now(),results[MD5],results[SHA1],results[SHA256],results[RIP160],length)

