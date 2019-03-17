#include <stdint.h>
#include "hash.h"

// SHA256 data. 

#define SHA256_BUF_OFFSET     (4)
#define SHA256_INPUT_BYTES   (64)  // Input bytes at a time
#define SHA256_SIZE_BYTES     (8)  // Bytes for internal input size representation
#define SHA256_RESULT_BYTES  (32)  // Hash result size in bytes
#define SHA256_LSW            (1)  // Least significant word for size
#define SHA256_MSW            (0)

typedef struct {
  JOINED H[SHA256_RESULT_BYTES/4];
  uint32_t count[SHA256_SIZE_BYTES/4];
} SHA256_CTX;

#define SHA256_MATCH(X,Y) (memcmp((X),(Y),SHA256_RESULT_BYTES))

void SHA256Init(SHA256_CTX *);
void SHA256Update(SHA256_CTX *,char * data,uint16_t length);
void SHA256AddExpandedHash(SHA256_CTX *,uint8_t * data);
void SHA256Final(SHA256_CTX *);