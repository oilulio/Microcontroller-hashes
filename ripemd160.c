/* RIPEMD160 algorithm

   From "RIPEMD-160: A Strengthened Version of RIPEMD", 
   by Hans Dobbertin, Antoon Bosselaers, Bart Preneel

   Optimised for size, both lower code size and *especially* low RAM.
   Within that context, optimised for speed.
   
   Note internal count is of bytes and whole is byte orientated.
   This means is non-standard compliant as can't hash a file larger 
   than 2^61 bits = 2^53 bytes.  Not serious limitation for
   microcontrollers!
   
   Also designed for 8 bit processors, so utilises code to avoid 
   shifting all 32 bits, where unnecessary.
   
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

Also tested, manually, for "abc" test vector 
---------------------------------------------------------------------------    */
#include "config.h"

#include "ripemd160.h"
#include <string.h> // memcpy

extern char buffer[MSG_LENGTH];  // MSG_LENGTH must be >=68 and 1st 68 chars will be destroyed
extern char hex[16];             // The ordered hex characters 0..9A..F

static void RIPEMD160Transform(RIPEMD160_CTX * context);
static void Encode(char *,JOINED *,uint8_t len);

#define PARITY(x,y,z)  ((x)^(y)^(z))
#define XCHOOSE(x,y,z) (((x)&(y))|((~x)&(z)))  // x chooses y or z.  "|" can be "^"
#define F3(x,y,z)      (((x)|(~y))^(z))
#define ZCHOOSE(x,y,z) (((z)&(x))|((~z)&(y)))  // z chooses x or y.  "|" can be "^"
#define F5(x,y,z)      ((x)^((y)|(~z)))

#define ROTL(x,n)      (((x)<<(n))|((x)>>(32-(n))))  // Works on uint32_t
 
// Medium rotation : 1 byte < shift < 2 bytes.  Converts in place.
#define MROTL(x,n) ({ uint8_t smsb=((x).lsb >>(16-(n)))|((x).slsb<<((n)-8));\
                      uint8_t msb =((x).slsb>>(16-(n)))|((x).smsb<<((n)-8));\
                          (x).slsb=((x).msb >>(16-(n)))|((x).lsb <<((n)-8));\
                          (x).lsb =((x).smsb>>(16-(n)))|((x).msb <<((n)-8));(x).smsb=smsb;(x).msb=msb; })                           
                           
#define ROTL10(x)  MROTL((x),10)

#define aL(S) ABCDE[(100-(S))%5] // Avoid negative %.  S in range 0 to 79
#define bL(S) ABCDE[(101-(S))%5]
#define cL(S) ABCDE[(102-(S))%5]
#define dL(S) ABCDE[(103-(S))%5]
#define eL(S) ABCDE[(104-(S))%5]

#define aR(S) PRIME[(100-(S))%5] 
#define bR(S) PRIME[(101-(S))%5]
#define cR(S) PRIME[(102-(S))%5]
#define dR(S) PRIME[(103-(S))%5]
#define eR(S) PRIME[(104-(S))%5]

uint8_t p[16]={7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8};

// --------------------------------------------------------------------------------
void RIPEMD160Init(RIPEMD160_CTX *context) 
{ 
context->count[0]=context->count[1]=0;

context->H[0].word32=0x67452301;
context->H[1].word32=0xEFCDAB89;
context->H[2].word32=0x98BADCFE;
context->H[3].word32=0x10325476;
context->H[4].word32=0xC3D2E1F0;
}
// --------------------------------------------------------------------------------
void RIPEMD160Update(RIPEMD160_CTX * context,char * input,uint16_t inputLen) 
{ // Adds inputLen characters to the hash, running RIPEMD160 Transfrom every time the
  // 64-character buffer is full
uint16_t i=0; 
uint8_t  index,partLen;

index=(((uint8_t)context->count[RIPEMD160_LSW])&0x3F);

if ((context->count[RIPEMD160_LSW]+=((uint32_t)inputLen))
                        < ((uint32_t)inputLen))          // Overflow
                                  context->count[RIPEMD160_MSW]++;
// unit16_t input length means count[RIPEMD160_MSW] can never increment directly

partLen=RIPEMD160_INPUT_BYTES-index;

if (inputLen>=partLen) {
  memcpy(&buffer[index+RIPEMD160_BUF_OFFSET],input,partLen);        // Fill rest of line
  RIPEMD160Transform(context);

  for (i=partLen;(i+63)<inputLen;i+=RIPEMD160_INPUT_BYTES) {
    memcpy(&buffer[RIPEMD160_BUF_OFFSET],&input[i],RIPEMD160_INPUT_BYTES); // Whole line
    RIPEMD160Transform(context);
  }
  index=0;
}
memcpy(&buffer[RIPEMD160_BUF_OFFSET+index],&input[i],inputLen-i);           // Leftovers
}
// -------------------------------------------------------------------------------- 
void RIPEMD160Final(RIPEMD160_CTX * context)
{
uint8_t index;
uint8_t restOfLine;

index=(((uint8_t)context->count[RIPEMD160_LSW])&0x3f);

buffer[RIPEMD160_BUF_OFFSET+index]=0x80;  // Indicator or last byte
restOfLine=RIPEMD160_INPUT_BYTES-1-index;                     // -1 accounts for 0x80

memset(&buffer[RIPEMD160_BUF_OFFSET+1+index],0,restOfLine);   // +1 because of 0x80 character
if (restOfLine<RIPEMD160_SIZE_BYTES) {                              // Can't fit on this line
  RIPEMD160Transform(context);
  memset(&buffer[RIPEMD160_BUF_OFFSET],0,RIPEMD160_INPUT_BYTES-RIPEMD160_SIZE_BYTES);  
}
context->count[RIPEMD160_MSW]+=(context->count[RIPEMD160_LSW]>>29); // Convert count to bits
context->count[RIPEMD160_LSW]<<=3;

Encode(&buffer[RIPEMD160_BUF_OFFSET+RIPEMD160_INPUT_BYTES-RIPEMD160_SIZE_BYTES],(JOINED *)context->count,RIPEMD160_SIZE_BYTES);
RIPEMD160Transform(context);

// State is now the result.  Expand it into hex chars into buffer for first RIPEMD160_RESULT_BYTES
Encode(buffer,(JOINED *)context->H,RIPEMD160_RESULT_BYTES);

memset(context,0,sizeof(*context));   // Clean sensitive intermediates
memset(&buffer[RIPEMD160_RESULT_BYTES],0,RIPEMD160_BUF_OFFSET+RIPEMD160_INPUT_BYTES-RIPEMD160_RESULT_BYTES);
}
// --------------------------------------------------------------------------------
void RIPEMD160Transform(RIPEMD160_CTX * context)
{  
uint32_t ABCDE[5];              // Local working copy Left Hand
uint32_t PRIME[5];              // Local working copy Right Hand
JOINED * X=(JOINED *)buffer;    // Alias only

for (uint8_t i=0,j=RIPEMD160_BUF_OFFSET;j<RIPEMD160_BUF_OFFSET+RIPEMD160_INPUT_BYTES;i++) {
  X[i].lsb =buffer[j++];  // N.B. Designed so i+1 can be copied into i, et seq
  X[i].slsb=buffer[j++];  
  X[i].smsb=buffer[j++];
  X[i].msb =buffer[j++];
}
memcpy(ABCDE,context->H,sizeof(ABCDE));
memcpy(PRIME,context->H,sizeof(PRIME)); 

uint32_t KL[]={0x0,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E}; // Compiler clever enought to not waste space on zeros!
uint32_t KR[]={0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x0};

uint8_t r[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
uint8_t q[]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12};

uint8_t sL[]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
              7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
              11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
              11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
              9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};

uint8_t sR[]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
              9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
              9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
              15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
              8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};

JOINED JT;

/* 30% slower, but 2k less code (and tidier!)

delete r[] and q[], replaxce with:

uint8_t rL[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
              7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
              3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
              1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
              4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
  
uint8_t rR[]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
              6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
              15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
              8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
              12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};  
  
for (uint8_t step=0;step<80;step++) {
  uint32_t T;
  switch (step>>4) {
    case(0): T=PARITY(bL(step),cL(step),dL(step));  break;
    case(1): T=XCHOOSE(bL(step),cL(step),dL(step)); break;
    case(2): T=F3(bL(step),cL(step),dL(step));      break;
    case(3): T=ZCHOOSE(bL(step),cL(step),dL(step)); break;
    case(4): T=F5(bL(step),cL(step),dL(step));      break;
 }
  aL(step)=ROTL(T+aL(step)+X[rL[step]].word32+KL[step>>4],sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  switch (step>>4) {
    case(4): T=PARITY(bR(step),cR(step),dR(step));  break;
    case(3): T=XCHOOSE(bR(step),cR(step),dR(step)); break;
    case(2): T=F3(bR(step),cR(step),dR(step));      break;
    case(1): T=ZCHOOSE(bR(step),cR(step),dR(step)); break;
    case(0): T=F5(bR(step),cR(step),dR(step));      break;
 }
  aR(step)=ROTL(T+aR(step)+X[rR[step]].word32+KR[step>>4],sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}*/

for (uint8_t step=0;step<16;step++) { 
  //r[step]=step;  Initialised this way
  //q[step]=(step*5+9)&0xF;
  uint32_t T=aL(step)+PARITY(bL(step),cL(step),dL(step))+X[r[step]].word32;//+KL[0]==0;
  aL(step)=ROTL(T,sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  T=aR(step)+F5(bR(step),cR(step),dR(step))+X[q[step]].word32+KR[0];
  aR(step)=ROTL(T,sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}
for (uint8_t step=0;step<16;step++) { 
  q[step]=r[p[step]];
}
for (uint8_t step=16;step<32;step++) { 
  r[step&0xF]=q[(9*(step&0xF)+5)&0xF];
  uint32_t T=aL(step)+XCHOOSE(bL(step),cL(step),dL(step))+X[q[step&0xF]].word32+KL[1];
  aL(step)=ROTL(T,sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  T=aR(step)+ZCHOOSE(bR(step),cR(step),dR(step))+X[r[step&0xF]].word32+KR[1];
  aR(step)=ROTL(T,sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}
for (uint8_t step=0;step<16;step++) { 
  r[step]=q[p[step]];
}
for (uint8_t step=32;step<48;step++) { 
  q[step&0xF]=r[(9*(step&0xF)+5)&0xF];
  uint32_t T=aL(step)+F3(bL(step),cL(step),dL(step))+X[r[step&0xF]].word32+KL[2];
  aL(step)=ROTL(T,sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  T=aR(step)+F3(bR(step),cR(step),dR(step))+X[q[step&0xF]].word32+KR[2];
  aR(step)=ROTL(T,sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}
for (uint8_t step=0;step<16;step++) { 
  q[step]=r[p[step]];
}
for (uint8_t step=48;step<64;step++) {
  r[step&0xF]=q[(9*(step&0xF)+5)&0xF];
  uint32_t T=aL(step)+ZCHOOSE(bL(step),cL(step),dL(step))+X[q[step&0xF]].word32+KL[3];
  aL(step)=ROTL(T,sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  T=aR(step)+XCHOOSE(bR(step),cR(step),dR(step))+X[r[step&0xF]].word32+KR[3];
  aR(step)=ROTL(T,sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}
for (uint8_t step=0;step<16;step++) { 
  r[step]=q[p[step]];
}
for (uint8_t step=64;step<80;step++) { 
  q[step&0xF]=r[(9*(step&0xF)+5)&0xF];
  uint32_t T=aL(step)+F5(bL(step),cL(step),dL(step))+X[r[step&0xF]].word32+KL[4];
  aL(step)=ROTL(T,sL[step])+eL(step);
  JT.word32=cL(step);
  ROTL10(JT);
  cL(step)=JT.word32;
  T=aR(step)+PARITY(bR(step),cR(step),dR(step))+X[q[step&0xF]].word32; //+KR[4]==0;
  aR(step)=ROTL(T,sR[step])+eR(step);
  JT.word32=cR(step);
  ROTL10(JT);
  cR(step)=JT.word32;
}

uint32_t T          =context->H[1].word32+cL(0)+dR(0);
context->H[1].word32=context->H[2].word32+dL(0)+eR(0);
context->H[2].word32=context->H[3].word32+eL(0)+aR(0);
context->H[3].word32=context->H[4].word32+aL(0)+bR(0);
context->H[4].word32=context->H[0].word32+bL(0)+cR(0);
context->H[0].word32=T;

memset(buffer,0,MSG_LENGTH);  // Zeroise intermediate data (could defer this line)
memset(ABCDE,0,sizeof(ABCDE));
memset(PRIME,0,sizeof(PRIME));
}
// --------------------------------------------------------------------------------
static void Encode(char *output,JOINED * input,const uint8_t len)
{
for (uint8_t i=0,j=0;j<len;i++) {
  output[j++]=input[i].lsb;  // N.B. Designed so i+1 can be copied into i, et seq
  output[j++]=input[i].slsb;
  output[j++]=input[i].smsb;
  output[j++]=input[i].msb;
}
}


