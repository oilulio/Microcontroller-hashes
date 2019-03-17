#include <stdint.h>
#include "hash.h"

// Constants for MD5Transform routine.

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define MD5_BUF_OFFSET     (4)
#define MD5_INPUT_BYTES   (64)  // Input bytes at a time
#define MD5_SIZE_BYTES     (8)  // Bytes for internal representation of size 
#define MD5_RESULT_BYTES  (16)  // Hash result size in bytes
#define MD5_LSW            (0)  // Least significant word for size
#define MD5_MSW            (1)

// MD5 context. 
typedef struct {
  JOINED state[MD5_RESULT_BYTES/4];
  uint32_t count[MD5_SIZE_BYTES/4];
} MD5_CTX;

#define MD5_MATCH(X,Y) (memcmp((X),(Y),MD5_RESULT_BYTES))

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *,char * data,uint16_t length);
void MD5AddExpandedHash(MD5_CTX * context,char * data);
void MD5Final(MD5_CTX *);