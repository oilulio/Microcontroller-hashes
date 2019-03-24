#include <stdint.h>
#include "hash.h"

// RIPEMD160 data. 

#define RIPEMD160_BUF_OFFSET     (4)
#define RIPEMD160_INPUT_BYTES   (64)  // Input bytes at a time
#define RIPEMD160_SIZE_BYTES     (8)  // Bytes for internal input representation of size 
#define RIPEMD160_RESULT_BYTES  (20)  // Hash result size in bytes
#define RIPEMD160_LSW            (0)  // Least significant word for size
#define RIPEMD160_MSW            (1)

typedef struct {
  JOINED H[RIPEMD160_RESULT_BYTES/4];
  uint32_t count[RIPEMD160_SIZE_BYTES/4];
} RIPEMD160_CTX;

#define RIPEMD160_MATCH(X,Y) (memcmp((X),(Y),RIPEMD160_RESULT_BYTES))

void RIPEMD160Init(RIPEMD160_CTX *);
void RIPEMD160Update(RIPEMD160_CTX *,char * data,uint16_t length);
void RIPEMD160AddExpandedHash(RIPEMD160_CTX *,uint8_t * data);
void RIPEMD160Final(RIPEMD160_CTX *);