#include <gtest/gtest.h>

#include "quadiron.h"

namespace cipher = quadiron::cipher;

#if 0
static int simple_rand(int n)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, n);
    return dis(gen);
}

static void randomize_buffer(uint8_t* buf, size_t size)
{
    for (u_int i = 0; i < size; i++)
        buf[i] = simple_rand(256);
}
#endif

TEST(CipherTest, Test1) // NOLINT
{
    cipher::CipherRlwe<uint16_t> cipher(cipher::CipherType::FOO);

    cipher.test();
}
