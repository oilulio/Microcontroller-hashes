/* SHA-1 algorithm
   Optimised for size, both lower code size and *especially* low RAM.
   
   Note internal count is of bytes and whole is byte orientated.
   This means is non-standard compliant as can't hash a file larger 
   than 2^61 bits = 2^53 bytes.  Not serious limitation for
   microcontrollers!
   
   Also designed for 8 bit processors, so (exploiting fixed shifts of SHA)
   utilises code to avoid shifting all 32 bits, where unnecessary.
   Significant speed improvement results (c15%), but messier code.
   
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

Network transmission is digest,length,start point in LFSR (i.e. not segment lengths)

Also tested, in debugger, for "abc" test vector  in FIPS-180-1 
and the 1,000,000 repetitions of 'a' test vector in FIPS-180-1 (c.130s at 16MHz)
---------------------------------------------------------------------------    
    
 */
#include "config.h"

#include "sha1.h"
#include <string.h> // memcpy

extern char buffer[MSG_LENGTH];  // MSG_LENGTH must be >=68 and 1st 68 chars will be destroyed

static void SHA1Transform(SHA1_CTX * context);
static void Encode(char *,JOINED *,uint8_t len);

#define PARITY(x,y,z)   ((x)^(y)^(z))
#define CHOOSE(x,y,z)   (((x)&(y))|((~x)&(z)))  // x chooses y or z.  "|" can be "^"
#define MAJORITY(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

#define a(S) ABCDE[(100-(S))%5] // Avoid negative %.  S in range 0 to 79
#define b(S) ABCDE[(101-(S))%5]
#define c(S) ABCDE[(102-(S))%5]
#define d(S) ABCDE[(103-(S))%5]
#define e(S) ABCDE[(104-(S))%5]

#define SROTR(x,n) ({ uint8_t tmp=(x).lsb<<(8-(n));(x).word32>>=(n);(x).msb|=tmp;})  
#define SROTL(x,n) ({ uint8_t tmp=(x).msb>>(8-(n));(x).word32<<=(n);(x).lsb|=tmp;})  
// Short rotation, exploits change in just one byte.  Works on JOINED, with n<8

// --------------------------------------------------------------------------------
void SHA1Init(SHA1_CTX *context) 
{ 
context->count[0]=context->count[1]=0;

context->H[0].word32=0x67452301;  // Top 4 same as MD5
context->H[1].word32=0xefcdab89;
context->H[2].word32=0x98badcfe;
context->H[3].word32=0x10325476;
context->H[4].word32=0xc3d2e1f0;
}
// --------------------------------------------------------------------------------
void SHA1Update(SHA1_CTX * context,char * input,uint16_t inputLen) 
{
uint16_t i=0; 
uint8_t  index,partLen;

index=(((uint8_t)context->count[SHA1_LSW])&0x3F);

if ((context->count[SHA1_LSW]+=((uint32_t)inputLen))
                        < ((uint32_t)inputLen))          // Overflow
                                  context->count[SHA1_MSW]++;
// unit16_t input length means count[SHA1_MSW] can never increment directly

partLen=SHA1_INPUT_BYTES-index;

if (inputLen>=partLen) {
  memcpy(&buffer[index+SHA1_BUF_OFFSET],input,partLen);       // Fill rest of line
  SHA1Transform(context);

  for (i=partLen;(i+SHA1_INPUT_BYTES-1)<inputLen;i+=SHA1_INPUT_BYTES) {
    memcpy(&buffer[SHA1_BUF_OFFSET],&input[i],SHA1_INPUT_BYTES);   // Whole line
    SHA1Transform(context);
  }
  index=0;
}
memcpy(&buffer[SHA1_BUF_OFFSET+index],&input[i],inputLen-i);  // Leftovers
}
// -------------------------------------------------------------------------------- 
void SHA1Final(SHA1_CTX * context)
{
uint8_t index;
uint8_t restOfLine;

index=(((uint8_t)context->count[SHA1_LSW])&0x3f);

buffer[SHA1_BUF_OFFSET+index]=0x80;  // Indicator or last byte
restOfLine=SHA1_INPUT_BYTES-1-index;            // -1 accounts for 0x80

memset(&buffer[SHA1_BUF_OFFSET+1+index],0,restOfLine);   // +1 because of 0x80 character
if (restOfLine<SHA1_SIZE_BYTES) {                              // Can't fit on this line
  SHA1Transform(context);
  memset(&buffer[SHA1_BUF_OFFSET],0,SHA1_INPUT_BYTES-SHA1_SIZE_BYTES);  
}
context->count[SHA1_MSW]+=(context->count[SHA1_LSW]>>29); // Convert count to bits
context->count[SHA1_LSW]<<=3;

Encode(&buffer[SHA1_BUF_OFFSET+SHA1_INPUT_BYTES-SHA1_SIZE_BYTES],(JOINED *)context->count,SHA1_SIZE_BYTES);

SHA1Transform(context);

// State is now the result.  Expand it into hex chars into buffer for first SHA1_RESULT_BYTES
Encode(buffer,(JOINED *)context->H,SHA1_RESULT_BYTES);

memset(context,0,sizeof(*context));   // Clean sensitive intermediates
memset(&buffer[SHA1_RESULT_BYTES],0,SHA1_BUF_OFFSET+SHA1_INPUT_BYTES-SHA1_RESULT_BYTES);
}
// --------------------------------------------------------------------------------
static void SHA1Transform(SHA1_CTX * context)
{  
uint32_t ABCDE[5];              // Local working copy
JOINED * W=(JOINED *)buffer;    // Alias only

for (uint8_t i=0,j=SHA1_BUF_OFFSET;j<SHA1_BUF_OFFSET+SHA1_INPUT_BYTES;i++) {
  W[i].msb =buffer[j++];  // N.B. Designed so i+1 can be copied into i, et seq
  W[i].smsb=buffer[j++];
  W[i].slsb=buffer[j++];
  W[i].lsb =buffer[j++];
}

const uint32_t K[]={0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6};

memcpy(ABCDE,context->H,sizeof(ABCDE));
  
// Round 0 .. 19  
JOINED tmp32;
for (uint8_t step=0;step<16;step++) {
  tmp32.word32=a(step);
  SROTL(tmp32,5);
  e(step)=(tmp32.word32+CHOOSE(b(step),c(step),d(step))+e(step)+W[step].word32+K[0]);
  tmp32.word32=b(step);
  SROTR(tmp32,2);
  b(step)=tmp32.word32;
}
for (uint8_t step=16;step<20;step++) {
  uint8_t s=(step&0x0f);
  W[s].word32=W[(s+13)&0x0f].word32^W[(s+8)&0x0f].word32^W[(s+2)&0x0f].word32^W[s].word32;
  SROTL(W[s],1);  // Without this line, this is the original SHA-0/FIPS 180, not 180-1 specification
  
  tmp32.word32=a(step);
  SROTL(tmp32,5);
  e(step)=(tmp32.word32+CHOOSE(b(step),c(step),d(step))+e(step)+W[s].word32+K[0]);
  tmp32.word32=b(step);
  SROTR(tmp32,2);
  b(step)=tmp32.word32;
}
// Round 20 .. 39
for (uint8_t step=20;step<40;step++) {
  uint8_t s=(step&0x0f);
  W[s].word32=W[(s+13)&0x0f].word32^W[(s+8)&0x0f].word32^W[(s+2)&0x0f].word32^W[s].word32;
  SROTL(W[s],1);  // Without this line, this is the original SHA-0/FIPS 180, not 180-1 specification
  
  tmp32.word32=a(step);
  SROTL(tmp32,5);
  e(step)=(tmp32.word32+PARITY(b(step),c(step),d(step))+e(step)+W[s].word32+K[1]);
  tmp32.word32=b(step);
  SROTR(tmp32,2);
  b(step)=tmp32.word32;
}
// Round 40 .. 59
for (uint8_t step=40;step<60;step++) {
  uint8_t s=(step&0x0f);
  W[s].word32=W[(s+13)&0x0f].word32^W[(s+8)&0x0f].word32^W[(s+2)&0x0f].word32^W[s].word32;
  SROTL(W[s],1);  // Without this line, this is the original SHA-0/FIPS 180, not 180-1 specification
  
  tmp32.word32=a(step);
  SROTL(tmp32,5);
  e(step)=(tmp32.word32+MAJORITY(b(step),c(step),d(step))+e(step)+W[s].word32+K[2]);
  tmp32.word32=b(step);
  SROTR(tmp32,2);
  b(step)=tmp32.word32;
}
// Round 60 .. 79
for (uint8_t step=60;step<80;step++) {
  uint8_t s=(step&0x0f);
  W[s].word32=W[(s+13)&0x0f].word32^W[(s+8)&0x0f].word32^W[(s+2)&0x0f].word32^W[s].word32;
  SROTL(W[s],1);  // Without this line, this is the original SHA-0/FIPS 180, not 180-1 specification
  
  tmp32.word32=a(step);
  SROTL(tmp32,5);
  e(step)=(tmp32.word32+PARITY(b(step),c(step),d(step))+e(step)+W[s].word32+K[3]);
  tmp32.word32=b(step);
  SROTR(tmp32,2);
  b(step)=tmp32.word32;
}

context->H[0].word32+=a(0);
context->H[1].word32+=b(0);
context->H[2].word32+=c(0);
context->H[3].word32+=d(0);
context->H[4].word32+=e(0);
 
memset(buffer,0,MSG_LENGTH);  // Zeroise intermediate data (could defer this line)
memset(ABCDE,0,sizeof(ABCDE));
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
