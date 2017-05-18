
#ifndef __MAIN_H__
#define __MAIN_H__ 1

#include <iostream>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include "gf.h"
#include "gfp.h"
#include "gf2n.h"

typedef enum
  {
    NTLEX_NOT_FOUND,
  } NtlException;

template<typename Type> struct Double {};
template<>              struct Double<uint32_t> {typedef uint64_t T;};
template<>              struct Double<uint64_t> {typedef unsigned __int128 T;};

template<typename Type> struct Quad {};
template<>              struct Quad<uint32_t> {typedef unsigned __int128 T;};

#endif
