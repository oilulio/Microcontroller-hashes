/*  SHA-256 algorithm
    Optimised for size, both lower code size and *especially* low RAM.
   
   Note internal count is of bytes and whole is byte orientated.
   Also designed for 8 bit processors, so (exploiting fixed shifts of SHA)
   utilises code to avoid shifting all 32 bits, where unnecessary.
   Approx 20% speed improvement results, but much messier code.
   
   Copyright (C) 2019  S Combes

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
    
-------------------------------- TESTING ----------------------------------
Tested on Atmega328P for at least 100,000 hashes with results transmitted over
network and confirmed by comparison with same hash in Python (hashlib).  Hashes 
produced by a byte sequence from a 16 bit LFSR.  Hash input uniformly distributed
in length from 0 to 1499 characters.  Entered into routine in random segments chosen
uniformly from 0 to 79 characters, varying segment to segment (i.e. not hash to hash).

Network transmission is length,start point in LFSR,digest (i.e. not segment lengths)

Also tested, in debugger, for "abc" test vector and over network for some much 
larger inputs (up to 750,000 characters)
---------------------------------------------------------------------------    
    
 */
#include "config.h"

#include "sha256.h"
#include <string.h> // memcpy

extern char buffer[MSG_LENGTH];  // MSG_LENGTH must be >=68 and 1st 68 chars will be destroyed
extern char hex[16];             // The ordered hex characters 0..9A..F

static void SHA256Transform(SHA256_CTX * context);
static void Encode(char *,JOINED *,uint8_t len);

#define CHOOSE(x,y,z)   (((x)&(y))|((~x)&(z)))  // x chooses y or z.  "|" can be "^"
#define MAJORITY(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define ROTR(x,n)      (((x)<<(32-(n)))|((x)>>(n)))  // Works on uint32_t
#define SROTR(x,n) ({ uint8_t tmp=(x).lsb<<(8-(n));(x).word32>>=(n);(x).msb|=tmp;})  
// Short rotation, exploits change in just one byte.  Works on JOINED, with n<8

#define XOR3(x,n1,n2)  ((x)^ROTR((x),(n1))^ROTR((x),(n2)))  // XORs x with two version of itself ROTR'd by n1,n2
//#define SIGMA0(x)   ((ROTR(x,2 ))^ROTR(x,13)^ROTR(x,22)) // Not used - optimised
//#define SIGMA1(x)   ((ROTR(x,6 ))^ROTR(x,11)^ROTR(x,25))
//#define sigma0(x)   ((ROTR(x,7 ))^ROTR(x,18)^((x)>>3 ))  // Not used - optimised
//#define sigma1(x)   ((ROTR(x,17))^ROTR(x,19)^((x)>>10))

#define a(S) ABCDEFGH[(0-(S))&7] // S in range 0 to 63
#define b(S) ABCDEFGH[(1-(S))&7]
#define c(S) ABCDEFGH[(2-(S))&7]
#define d(S) ABCDEFGH[(3-(S))&7]
#define e(S) ABCDEFGH[(4-(S))&7]
#define f(S) ABCDEFGH[(5-(S))&7]
#define g(S) ABCDEFGH[(6-(S))&7]
#define h(S) ABCDEFGH[(7-(S))&7]


// --------------------------------------------------------------------------------
void SHA256Init(SHA256_CTX *context) 
{ 
context->count[0]=context->count[1]=0;

context->H[0].word32=0x6a09e667;
context->H[1].word32=0xbb67ae85;
context->H[2].word32=0x3c6ef372;
context->H[3].word32=0xa54ff53a;
context->H[4].word32=0x510e527f;
context->H[5].word32=0x9b05688c;
context->H[6].word32=0x1f83d9ab;
context->H[7].word32=0x5be0cd19;
}
// --------------------------------------------------------------------------------
void SHA256Update(SHA256_CTX * context,char * input,uint16_t inputLen) 
{ // Adds inputLen characters to the hash, running SHA256Transfrom every time the
  // 64-character buffer is full
uint16_t i=0; 
uint8_t  index,partLen;

index=(((uint8_t)context->count[SHA256_LSW])&0x3F);

if ((context->count[SHA256_LSW]+=((uint32_t)inputLen))
                        < ((uint32_t)inputLen))          // Overflow
                                  context->count[SHA256_MSW]++;
// unit16_t input length means count[SHA256_MSW] can never increment directly

partLen=SHA256_INPUT_BYTES-index;

if (inputLen>=partLen) {
  memcpy(&buffer[index+SHA256_BUF_OFFSET],input,partLen);       // Fill rest of line
  SHA256Transform(context);

  for (i=partLen;(i+SHA256_INPUT_BYTES-1)<inputLen;i+=SHA256_INPUT_BYTES) {
    memcpy(&buffer[SHA256_BUF_OFFSET],&input[i],SHA256_INPUT_BYTES);   // Whole line
    SHA256Transform(context);
  }
  index=0;
}
memcpy(&buffer[SHA256_BUF_OFFSET+index],&input[i],inputLen-i);  // Leftovers
}
// -------------------------------------------------------------------------------- 
void SHA256AddExpandedHash(SHA256_CTX * context,uint8_t * data)
{ // Adds a pre-existing hash result to the hash, noting that the storage format is
  // the byte stream, and the function expects the lower case, human readable, hex 
  // representation.  To add just the binary hash, as used in Bitcoin, use 
  // SHA256Update() directly.
  
char byte[2]; 
for (uint8_t i=0;i<SHA256_RESULT_BYTES;i++) {
  byte[0]=hex[data[i]>>4]|0x20; // Ensures lower case (known subset of chars)
  byte[1]=hex[data[i]&0x0F]|0x20; 
  SHA256Update(context,byte,2);
}
}
// -------------------------------------------------------------------------------- 
void SHA256Final(SHA256_CTX * context)
{
uint8_t index;
uint8_t restOfLine;

index=(((uint8_t)context->count[SHA256_LSW])&0x3f);

buffer[SHA256_BUF_OFFSET+index]=0x80;     // Indicator for last byte
restOfLine=SHA256_INPUT_BYTES-1-index;    // -1 accounts for 0x80

memset(&buffer[SHA256_BUF_OFFSET+1+index],0,restOfLine);   // +1 because of 0x80 character
if (restOfLine<SHA256_SIZE_BYTES) {                              // Can't fit on this line
  SHA256Transform(context);
  memset(&buffer[SHA256_BUF_OFFSET],0,SHA256_INPUT_BYTES-SHA256_SIZE_BYTES);  
}
context->count[SHA256_MSW]+=(context->count[SHA256_LSW]>>29); // Convert count to bits
context->count[SHA256_LSW]<<=3;

Encode(&buffer[SHA256_BUF_OFFSET+SHA256_INPUT_BYTES-SHA256_SIZE_BYTES],(JOINED *)context->count,SHA256_SIZE_BYTES);

SHA256Transform(context);

// State is now the result.  Expand it into hex chars into buffer for first SHA256_RESULT_BYTES
Encode(buffer,(JOINED *)context->H,SHA256_RESULT_BYTES);

memset(context,0,sizeof(*context));   // Clean sensitive intermediates
memset(&buffer[SHA256_RESULT_BYTES],0,SHA256_BUF_OFFSET+SHA256_INPUT_BYTES-SHA256_RESULT_BYTES);
}
// --------------------------------------------------------------------------------
void SHA256Transform(SHA256_CTX * context)
{  
uint32_t ABCDEFGH[8];              // Local working copy
JOINED * W=(JOINED *)buffer;       // Alias only

for (uint8_t i=0,j=SHA256_BUF_OFFSET;j<SHA256_BUF_OFFSET+SHA256_INPUT_BYTES;i++) {
  W[i].msb =buffer[j++];  // N.B. Designed so i+1 can be copied into i, et seq
  W[i].smsb=buffer[j++];
  W[i].slsb=buffer[j++];
  W[i].lsb =buffer[j++];
}
const uint32_t K[]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

memcpy(ABCDEFGH,context->H,sizeof(ABCDEFGH));
  
// Round 0 .. 63  

JOINED tmpJ;
for (uint8_t step=0;step<64;step++) { 
  if (step&0xF0) { // 16 and above
  // Whole block could be written : W[step&0xF].word32+=sigma1(W[(step-2)&0xF].word32)+W[(step-7)&0xF].word32+sigma0(W[(step-15)&0xF].word32);

    tmpJ.word32=W[(step-15)&0xF].word32;
    uint32_t tmp1=tmpJ.word32>>3;
    SROTR(tmpJ,7);
    
    tmp1^=ROTR(tmpJ.word32,11);
    W[step&0xF].word32+=(tmp1^tmpJ.word32)+W[(step-7)&0xF].word32;
    
    JOINED tmpA,tmpB;
    tmpA.word32=ROTR(W[(step-2)&0xF].word32,17);
    
    uint8_t tmp8=tmpA.lsb<<6;
    tmpB.word32=tmpA.word32>>2;  // Keep intermediate
    tmpB.msb|=tmp8;
    tmpA.word32^=W[(step-2)&0xF].word32>>10;
    W[step&0xF].word32+=(tmpA.word32^tmpB.word32);
  } 
  tmpJ.word32=XOR3(e(step),5,19);
  SROTR(tmpJ,6);  
  h(step)+=tmpJ.word32+CHOOSE(e(step),f(step),g(step))+K[step]+W[step&0xF].word32;
  d(step)+=h(step);
  tmpJ.word32=XOR3(a(step),11,20);
  SROTR(tmpJ,2);
  h(step)+=tmpJ.word32+MAJORITY(a(step),b(step),c(step));
}

context->H[0].word32+=a(0);
context->H[1].word32+=b(0);
context->H[2].word32+=c(0);
context->H[3].word32+=d(0);
context->H[4].word32+=e(0);
context->H[5].word32+=f(0);
context->H[6].word32+=g(0);
context->H[7].word32+=h(0);
 
memset(buffer,0,MSG_LENGTH);  // Zeroise intermediate data (could defer this line)
memset(ABCDEFGH,0,sizeof(ABCDEFGH));
}
// --------------------------------------------------------------------------------
static void Encode(char *output,JOINED * input,const uint8_t len)
{
for (uint8_t i=0,j=0;j<len;i++) {
  output[j++]=input[i].msb;  // N.B. Designed so i+1 can be copied into i, et seq
  output[j++]=input[i].smsb;
  output[j++]=input[i].slsb;
  output[j++]=input[i].lsb;
}
}
// --------------------------------------------------------------------------------
/*
To TEST in Debugger use main.c that reads:

#include <avr/io.h>
#include "hash.h"
#include "sha256.h"
#include "config.h" // Which should at least read :

// #define MSG_LENGTH (68)  
// #define LITTLEENDIAN (1)

// END OF config.h

char buffer[MSG_LENGTH];
char hex[]="0123456789ABCDEF";

int main(void)
{

SHA256_CTX sha256context;
SHA256Init(&sha256context);
SHA256Update(&sha256context,"abc",3);
SHA256Final(&sha256context);
// Whole hash of "abc" takes 128,986 cycles.

SHA256Init(&sha256context);  // Only here to give Debugger a breakpoint
// Inspect contents of buffer to see hash

while (1)   {  }
}
*/