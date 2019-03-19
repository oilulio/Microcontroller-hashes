#ifndef HASH_H
#define HASH_H

#include "config.h"

typedef struct { 
  union {
    uint32_t word32;
    char * bytes;
    struct {
#ifdef LITTLEENDIAN
      char lsb;
      char slsb;
      char smsb;
      char msb;
#else
      char msb;
      char smsb;
      char slsb;
      char lsb;
#endif
    };
  };
} JOINED;

#endif