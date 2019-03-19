/* MD5 algorithm
   Adapted/enhanced from reference code in RFC 1321
   and optimised for size, both lower code size and *especially* lower RAM.
 
  Therefore : "derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm" :
  Original Copyright (C) 1991-2,RSA Data Security, Inc. Created 1991. All
  rights reserved.  
  
  This version Copyright (C) 2019  S Combes

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    
   Note internal count is now of bytes and whole is byte orientated.
   Slightly less flexible, but would allow further compaction of count.
   
   MD5 is essentially operating on a bitstream, but is Littleendian
   when entering the bit count, and RFC 1321 treats words as Littleendian
   when written e.g. "word A: 01 23 45 67", which is 0x67452301 
   It then uses left shift, which is only 'left' when considered Bigendian.
   
-------------------------------- TESTING ----------------------------------
Tested on Atmega328P for at least 100,000 hashes with results transmitted over
network and confirmed by comparison with same hash in Python (hashlib).  Hashes 
produced by a byte sequence from a 16 bit LFSR.  Hash input uniformly distributed
in length from 0 to 1499 characters.  Entered into routine in random segments chosen
uniformly from 0 to 79 characters, varying segment to segment (i.e. not hash to hash).

Network transmission is length,start point in LFSR,digest (i.e. not segment lengths)

Also tested, manually, for RFC 1321 test vectors
---------------------------------------------------------------------------
 */
#include "config.h"

#include "md5.h"
#include <string.h> // memcpy

extern char buffer[MSG_LENGTH];  // MSG_LENGTH must be >=68 and 1st 68 chars will be destroyed
extern char hex[16];    // The ordered hex characters 0..9A..F, but note we want lower case 
// extern to save space when used elsewhere.  Can use directly instead :
// char hex[]="0123456789abcdef"

static void MD5Transform(MD5_CTX * context);
static void Encode(char *,JOINED *,uint8_t len);

#define PARITY(x,y,z) ((x)^(y)^(z))
#define XCHOOSE(x,y,z) (((x)&(y))|((~x)&(z)))  // x chooses y or z.  "|" can be "^"
#define ZCHOOSE(x,y,z) (((z)&(x))|((~z)&(y)))  // z chooses x or y.  "|" can be "^"

#define F(x,y,z) XCHOOSE(x,y,z)
#define G(x,y,z) ZCHOOSE(x,y,z)
#define H(x,y,z) PARITY(x,y,z)
#define I(x,y,z) ((y)^((x)|(~z)))

#define a(S) ABCD[(0-S)&3]
#define b(S) ABCD[(1-S)&3]
#define c(S) ABCD[(2-S)&3]
#define d(S) ABCD[(3-S)&3]

#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
// --------------------------------------------------------------------------------
void MD5Init(MD5_CTX *context) 
{ 
context->count[0]=context->count[1]=0;

context->state[0].word32=0x67452301;
context->state[1].word32=0xefcdab89;
context->state[2].word32=0x98badcfe;
context->state[3].word32=0x10325476;
}
// --------------------------------------------------------------------------------
void MD5Update(MD5_CTX * context,char * input,uint16_t inputLen) 
{
uint16_t i=0; 
uint8_t  index,partLen;

index=(((uint8_t)context->count[MD5_LSW])&0x3F);

if ((context->count[MD5_LSW]+=((uint32_t)inputLen))
                        < ((uint32_t)inputLen))          // Overflow
                                  context->count[MD5_MSW]++;
// unit16_t input length means count[MD5_LSW] can never increment directly

partLen=MD5_INPUT_BYTES-index;

if (inputLen>=partLen) {
  memcpy(&buffer[index+MD5_BUF_OFFSET],input,partLen);       // Fill rest of line
  MD5Transform(context);

  for (i=partLen;(i+63)<inputLen;i+=MD5_INPUT_BYTES) {
    memcpy(&buffer[MD5_BUF_OFFSET],&input[i],MD5_INPUT_BYTES);   // Whole line
    MD5Transform(context);
  }
  index=0;
}
memcpy(&buffer[MD5_BUF_OFFSET+index],&input[i],inputLen-i);  // Leftovers
}
// -------------------------------------------------------------------------------- 
void MD5AddExpandedHash(MD5_CTX * context,char * data)
{ // Adds a pre-existing hash result to the hash, noting that the storage format is
  // the byte stream, and the function expects the lower case, human readable, hex 
  // representation.  This is the process used in RFC2069.  To add just the binary
  // hash use MD5Update() directly.
  
uint8_t byte[2]; 
for (uint8_t i=0;i<MD5_RESULT_BYTES;i++) {
  byte[0]=hex[data[i]>>4]|0x20;  // Ensures lower case (known subset of chars)
  byte[1]=hex[data[i]&0x0F]|0x20; 
  MD5Update(context,(char *)byte,2);
}
}
// -------------------------------------------------------------------------------- 
void MD5Final(MD5_CTX * context)
{
uint8_t index;
uint8_t restOfLine;

index=(((uint8_t)context->count[MD5_LSW])&0x3f);

buffer[MD5_BUF_OFFSET+index]=0x80;  // Indicator or last byte
restOfLine=63-index;            // 63 accounts for 0x80

memset(&buffer[MD5_BUF_OFFSET+1+index],0,restOfLine);   // +1 because of 0x80 character
if (restOfLine<MD5_SIZE_BYTES) {                              // Can't fit on this line
  MD5Transform(context);
  memset(&buffer[MD5_BUF_OFFSET],0,MD5_INPUT_BYTES-MD5_SIZE_BYTES);  
}
context->count[MD5_MSW]+=(context->count[MD5_LSW]>>29); // Convert count to bits
context->count[MD5_LSW]<<=3;

Encode(&buffer[MD5_BUF_OFFSET+MD5_INPUT_BYTES-MD5_SIZE_BYTES],(JOINED *)context->count,MD5_SIZE_BYTES);
MD5Transform(context);

// State is now the result.  Expand it into hex chars into buffer for first MD5_RESULT_BYTES
Encode(buffer,(JOINED *)context->state,MD5_RESULT_BYTES);

memset(context,0,sizeof(*context));   // Clean sensitive intermediates
memset(&buffer[MD5_RESULT_BYTES],0,MD5_BUF_OFFSET+MD5_INPUT_BYTES-MD5_RESULT_BYTES);
}
// --------------------------------------------------------------------------------
static void MD5Transform(MD5_CTX * context)
{  
uint32_t ABCD[4];             // Local working copy
JOINED * x=(JOINED *)buffer;  // Alias only

// ********************************************************************
// Convert bytestream into words on which addition can work
for (uint8_t i=0,j=MD5_BUF_OFFSET;j<MD5_BUF_OFFSET+MD5_INPUT_BYTES;i++) {
  x[i].lsb =buffer[j++];  // N.B. Designed so i+1 can be copied into i, et seq
  x[i].slsb=buffer[j++];  
  x[i].smsb=buffer[j++];
  x[i].msb =buffer[j++];
}

const uint32_t T[]={
             0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
             0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
             0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
             0x6b901122,0xfd987193,0xa679438e,0x49b40821,
             0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
             0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
             0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
             0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
             0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
             0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
             0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
             0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
             0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
             0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
             0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
             0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
  
memcpy(ABCD,context->state,sizeof(ABCD));
  
const uint8_t SRND1[]={S11,S12,S13,S14};
const uint8_t SRND2[]={S21,S22,S23,S24};
const uint8_t SRND3[]={S31,S32,S33,S34};
const uint8_t SRND4[]={S41,S42,S43,S44};
 
for (uint8_t step=0;step<16;step++) {
  uint32_t z=(a(step)+F(b(step),c(step),d(step))+x[step].word32+T[step]);
  a(step)=b(step)+ROTL(z,SRND1[step&3]);
}
for (uint8_t step=0;step<16;step++) {
  uint32_t z=(a(step)+G(b(step),c(step),d(step))+x[(step*5+1)&0x0F].word32+T[step+16]);
  a(step)=b(step)+ROTL(z,SRND2[step&3]);
}
for (uint8_t step=0;step<16;step++) {
  uint32_t z=(a(step)+H(b(step),c(step),d(step))+x[(step*3+5)&0x0F].word32+T[step+32]);
  a(step)=b(step)+ROTL(z,SRND3[step&3]);
}
for (uint8_t step=0;step<16;step++) {
  uint32_t z=(a(step)+I(b(step),c(step),d(step))+x[(step*7)&0x0F].word32+T[step+48]);
  a(step)=b(step)+ROTL(z,SRND4[step&3]);
}
context->state[0].word32+=a(0);
context->state[1].word32+=b(0);
context->state[2].word32+=c(0);
context->state[3].word32+=d(0);
 
memset(buffer,0,MSG_LENGTH);  // Zeroise intermediate data (could defer this line)
memset(ABCD,0,sizeof(ABCD));
}
// --------------------------------------------------------------------------------
static void Encode(char *output,JOINED * input,const uint8_t len)
{ // Bytestream returns the littleendian equivalent of a word32, whatever its internal representation
for (uint8_t i=0,j=0;j<len;i++) {
  output[j++]=input[i].lsb;  // N.B. Designed so i+1 can be copied into i, et seq
  output[j++]=input[i].slsb;
  output[j++]=input[i].smsb;
  output[j++]=input[i].msb;
}
}
