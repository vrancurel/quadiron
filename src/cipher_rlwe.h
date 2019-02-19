#ifndef __QUAD_CIPHER_RLWE_H__
#define __QUAD_CIPHER_RLWE_H__

#include "arith.h"
#include "cipher_base.h"
#include "fft_2n.h"
#include "fft_naive.h"
#include "gf_prime.h"
#include "vec_poly.h"
#include "vec_vector.h"

namespace quadiron {
namespace cipher {

/** Learning-With-Error over RING (R-LWE) public key encryption scheme
 *
 * Ring-LWE in Polynomial Rings
 * Leo Ducas and Alain Durmus
 *
 * Efficient Software Implementation of Ring-LWE Encryption
 * Ruan de Clercq, Sujoy Sinha Roy, Frederik Vercauteren, and Ingrid Verbauwhede
 */
template <typename T>
class CipherRlwe : public CipherBase<T> {
  private:
    unsigned n;
    unsigned q;
    unsigned qby2;
    unsigned qby4;
    unsigned qby4times3;

    std::unique_ptr<gf::Field<T>> gf = nullptr;
    // XXX had issues with unique_ptr<vec::Vector<>>
    std::unique_ptr<fft::FourierTransform<T>> fft = nullptr;

    int k;
    std::uniform_int_distribution<T>* uniform_dis = nullptr;
    std::binomial_distribution<int>* binomial_dis = nullptr;
    void rand_uniform(vec::Vector<T>& vec);
    void rand_bit_uniform(vec::Vector<T>& vec);
    void rand_binomial(vec::Vector<T>& vec);

  public:
    CipherRlwe(CipherType type);
    ~CipherRlwe();
    void key_gen(vec::Vector<T>& _r2, vec::Vector<T>& _a, vec::Vector<T>& _p);
    void encrypt(
        vec::Vector<T>& _c1,
        vec::Vector<T>& _c2,
        vec::Vector<T>& m,
        vec::Vector<T>& _a,
        vec::Vector<T>& _p);
    void decrypt(
        vec::Vector<T>& m,
        vec::Vector<T>& _c1,
        vec::Vector<T>& _c2,
        vec::Vector<T>& _r2);
    void test();
};

template <typename T>
CipherRlwe<T>::CipherRlwe(CipherType type) : CipherBase<T>(type)
{
    k = 16;
    n = 256;
    q = 7681;
    // n = 512;
    // q = 12289;
    // n = 1024;
    // q = 12289;

    qby2 = q / 2;
    qby4 = q / 4;
    qby4times3 = qby4 * 3;

    uniform_dis = new std::uniform_int_distribution<T>(0, q - 1);
    binomial_dis = new std::binomial_distribution<int>(k * 2, 0.5);

    gf = gf::alloc<gf::Field<T>, gf::Prime<T>>(q);
    this->fft = std::make_unique<fft::Radix2<T>>(*gf, n, n);
}

template <typename T>
CipherRlwe<T>::~CipherRlwe()
{
    delete uniform_dis;
    delete binomial_dis;
}

/** Generate a random polynomial sampled uniformely in the field
 *
 * @param vec the random polynomial
 */
template <typename T>
void CipherRlwe<T>::rand_uniform(vec::Vector<T>& poly)
{
    for (unsigned i = 0; i < n; i++) {
        poly.set(i, (*uniform_dis)(prng()));
    }
}

/** Generate a random polynomial sampled uniformely in the field with bit
 * coefficients
 *
 * @param vec the random bit polynomial
 */
template <typename T>
void CipherRlwe<T>::rand_bit_uniform(vec::Vector<T>& poly)
{
    for (unsigned i = 0; i < n; i++) {
        poly.set(i, (*uniform_dis)(prng()) % 2);
    }
}

/** Generate the error polynomial sampled acc/to the error distribution in the
 * field mu = 0 and sigma^2 = k/2
 *
 * @param vec the error polynomial
 */
template <typename T>
void CipherRlwe<T>::rand_binomial(vec::Vector<T>& poly)
{
    for (unsigned i = 0; i < n; i++) {
        int r = (*binomial_dis)(prng()) - k;
        if (r < 0)
            r = q + r;
        poly.set(i, r);
    }
}

/** Generate the keys
 *
 * a <- uniform distribution
 * r1, r2 <= error distribution
 *
 * _a = NTT(a)
 * _r1 = NTT(r1)
 * _r2 = NTT(r2)
 * _p = _r1 - _a * _r2
 *
 * Private key is _r2
 * Public key is (_a, _p)
 *
 */
template <typename T>
void CipherRlwe<T>::key_gen(
    vec::Vector<T>& _r2,
    vec::Vector<T>& _a,
    vec::Vector<T>& _p)
{
    vec::Vector<T> a(*gf, n), p(*gf, n), r1(*gf, n), _r1(*gf, n), r2(*gf, n);
    rand_uniform(a);
    this->fft->fft(_a, a);
    rand_binomial(r1);
    this->fft->fft(_r1, r1);
    rand_binomial(r2);
    this->fft->fft(_r2, r2);

    for (unsigned i = 0; i < n; i++) {
        _p.set(i, gf->sub(_r1.get(i), gf->mul(_a.get(i), _r2.get(i))));
    }
}

/** Encrypt message with public key
 *
 * e1, e2, e3 <- error distribution
 *
 * _e1 = NTT(e1)
 * _e2 = NTT(e2)
 * _c1 = _a * _e1 + _e2
 * _c2 = _p * _e1 + NTT(e3 + encode(m))
 *
 * Encoded message is (_c1, _c2)
 */
template <typename T>
void CipherRlwe<T>::encrypt(
    vec::Vector<T>& _c1,
    vec::Vector<T>& _c2,
    vec::Vector<T>& m,
    vec::Vector<T>& _a,
    vec::Vector<T>& _p)
{
    vec::Vector<T> e1(*gf, n), e2(*gf, n), e3(*gf, n);
    vec::Vector<T> _e1(*gf, n), _e2(*gf, n);
    rand_binomial(e1);
    this->fft->fft(_e1, e1);
    rand_binomial(e2);
    this->fft->fft(_e2, e2);
    rand_binomial(e3);

    vec::Vector<T> e3m(*gf, n), _e3m(*gf, n);
    for (unsigned i = 0; i < n; i++) {
        e3m.set(i, gf->add(e3.get(i), m.get(i) ? qby2 : 0));
    }
    this->fft->fft(_e3m, e3m);

    for (unsigned i = 0; i < n; i++) {
        _c1.set(i, gf->add(_e2.get(i), gf->mul(_a.get(i), _e1.get(i))));
        _c2.set(i, gf->add(_e3m.get(i), gf->mul(_p.get(i), _e1.get(i))));
    }
}

/** Decrypt message with private key
 *
 * d = INTT(_c1 * _r2 + _c2)
 * m = decode(d)
 *
 * Decrypted message is m
 */
template <typename T>
void CipherRlwe<T>::decrypt(
    vec::Vector<T>& m,
    vec::Vector<T>& _c1,
    vec::Vector<T>& _c2,
    vec::Vector<T>& _r2)
{
    vec::Vector<T> _d(*gf, n), d(*gf, n);

    for (unsigned i = 0; i < n; i++) {
        _d.set(i, gf->add(_c2.get(i), gf->mul(_c1.get(i), _r2.get(i))));
    }

    this->fft->ifft(d, _d);

    for (unsigned i = 0; i < n; i++) {
        m.set(i, (d.get(i) > qby4 && d.get(i) < qby4times3) ? 1 : 0);
    }
}

template <typename T>
void CipherRlwe<T>::test()
{
    vec::Vector<T> _r2(*gf, n), _a(*gf, n), _p(*gf, n);
    vec::Vector<T> m(*gf, n);
    vec::Vector<T> _c1(*gf, n), _c2(*gf, n);
    vec::Vector<T> m1(*gf, n);

    std::cout << "key_gen\n";
    key_gen(_r2, _a, _p);

    std::cout << "encrypt\n";
    rand_bit_uniform(m);
    encrypt(_c1, _c2, m, _a, _p);

    std::cout << "decrypt\n";
    decrypt(m1, _c1, _c2, _r2);

    if (!(m1 == m)) {
        std::cout << "decrypt issue\n";
        m.dump();
        m1.dump();
    }
}

} // namespace cipher
} // namespace quadiron
#endif
