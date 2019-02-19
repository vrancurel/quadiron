#ifndef __QUAD_CIPHER_BASE_H__
#define __QUAD_CIPHER_BASE_H__

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>
#include <sys/time.h>

#include "gf_base.h"
#include "misc.h"

namespace quadiron {

/** Encryption-Scheme implementations. */
namespace cipher {

enum class CipherType { FOO };

/** Base class for Ciphers */
template <typename T>
class CipherBase {
  public:
    CipherType type;

    CipherBase(CipherType type);
    virtual ~CipherBase() = default;

    // virtual void key_gen() = 0;
    // void encrypt_block(std::vector<uint8_t> buf, size_t size) = 0;
    // void decrypt_block(std::vector<uint8_t> buf, size_t size) = 0;
};

/// Create an encoder.
template <typename T>
CipherBase<T>::CipherBase(CipherType type)
{
    this->type = type;
}

} // namespace cipher
} // namespace quadiron

#endif
