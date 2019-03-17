#include <stdint.h>
#include "hash.h"

// SHA1 data. 

#define SHA1_BUF_OFFSET     (4)
#define SHA1_INPUT_BYTES   (64)  // Input bytes at a time
#define SHA1_SIZE_BYTES     (8)  // Bytes for internal input representation of size
#define SHA1_RESULT_BYTES  (20)  // Hash result size in bytes
#define SHA1_LSW            (1)  // Least significant word for size
#define SHA1_MSW            (0)

typedef struct {
  JOINED H[SHA1_RESULT_BYTES/4];
  uint32_t count[SHA1_SIZE_BYTES/4];
} SHA1_CTX;

#define SHA1_MATCH(X,Y) (memcmp((X),(Y),SHA1_RESULT_BYTES))

void SHA1Init(SHA1_CTX *);
void SHA1Update(SHA1_CTX *,char * data,uint16_t length);
void SHA1Final(SHA1_CTX *);