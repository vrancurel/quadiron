/* -*- mode: c++ -*- */
/*
 * Copyright 2017-2018 Scality
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __QUAD_VEC_VECTOR_H__
#define __QUAD_VEC_VECTOR_H__

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include "core.h"
#include "gf_ring.h"
#include "simd/simd.h"
#include "vec_cast.h"

namespace quadiron {

template <typename T>
class Poly;

/** Low-level wrappers/helpers around memory buffer. */
namespace vec {

// Forward declarations.
template <typename>
class Vector;
template <typename T>
bool operator==(const Vector<T>& lhs, const Vector<T>& rhs);

/** A 1D vector.
 *
 * Its size can be defined at runtime (unlike std::array) but cannot changes
 * after its creation (unlike std::vector).
 *
 * It can owns its memory or be used as a wrapper around pre-allocated data.
 */
template <typename T>
class Vector {
  public:
    const gf::RingModN<T>* rn;

    Vector(const gf::RingModN<T>& rn, int n, T* mem = nullptr, int mem_len = 0);
    Vector(const gf::RingModN<T>& rn, std::initializer_list<T> values);
    Vector(const Vector& other);
    Vector(Vector&& other) noexcept;
    Vector& operator=(const Vector& other);
    Vector& operator=(Vector&& other) noexcept;
    virtual ~Vector();

    const gf::RingModN<T>& get_gf(void) const;
    virtual int get_n(void) const;
    int get_mem_len(void) const;
    virtual void zero_fill(void);
    void fill(T val);
    virtual void set(int i, T val);
    virtual const T& get(int i) const;
    T* get_mem() const;
    void set_mem(T* mem, int mem_len);
    void mul_scalar(T scalar);
    void mul_beta(T beta);
    void hadamard_mul(Vector<T>* v);
    void add(Vector<T>* v);
    void add(Vector<T>* v, int offset);
    void add_mutual(Vector<T>* v);
    void add_mutual(Vector<T>* v, int offset);
    void add_mutual(Vector<T>* v, int offset, int len);
    void copy(Vector<T>* v);
    void copy(Vector<T>* v, int n);
    void copy(Vector<T>* v, int n, int offset);
    void copy(Vector<T>* v, int n, int dest_offset, int src_offset);
    friend bool operator==<T>(const Vector<T>& lhs, const Vector<T>& rhs);
    virtual void neg();
    void to_poly(Poly<T>* poly);
    void rand();
    virtual void dump(void) const;
    void sort();
    void swap(unsigned i, unsigned j);

    friend void swap(Vector<T>& lhs, Vector<T>& rhs) noexcept
    {
        using std::swap;

        swap(lhs.rn, rhs.rn);
        swap(lhs.n, rhs.n);
        swap(lhs.mem, rhs.mem);
        swap(lhs.mem_len, rhs.mem_len);
        swap(lhs.new_mem, rhs.new_mem);
        swap(lhs.allocator, rhs.allocator);
    }

  protected:
    int n;

  private:
    T* mem;
    int mem_len;
    bool new_mem;
    simd::AlignedAllocator<T> allocator;

    void destroy()
    {
        if (new_mem) {
            this->allocator.deallocate(this->mem, n);
        }
    }
};

template <typename T>
Vector<T>::Vector(const gf::RingModN<T>& rn, int n, T* mem, int mem_len)
    : rn(&rn), n(n)
{
    if (mem == nullptr) {
        this->mem = this->allocator.allocate(n);
        this->mem_len = n;
        this->new_mem = true;
    } else {
        this->mem = mem;
        this->mem_len = mem_len;
        this->new_mem = false;
    }
}

template <typename T>
Vector<T>::Vector(const gf::RingModN<T>& rn, std::initializer_list<T> values)
    : Vector(rn, values.size())
{
    int i = 0;
    for (auto value : values) {
        mem[i++] = value;
    }
}

template <typename T>
Vector<T>::Vector(Vector const& other)
    : rn(other.rn), n(other.n), new_mem(other.new_mem),
      allocator(other.allocator)
{
    if (new_mem) {
        this->mem = this->allocator.allocate(other.mem_len);
        std::copy_n(this->mem, other.mem_len, other.mem);
    } else {
        this->mem = other.mem;
    }
    this->mem_len = other.mem_len;
}

template <typename T>
Vector<T>::Vector(Vector&& other) noexcept
    : rn(other.rn), n(other.n), mem(std::exchange(other.mem, nullptr)),
      mem_len(other.mem_len), new_mem(other.new_mem), allocator(other.allocator)
{
}

template <typename T>
Vector<T>& Vector<T>::operator=(const Vector<T>& other)
{
    Vector<T> tmp(other);
    swap(*this, tmp);
    return *this;
}

template <typename T>
Vector<T>& Vector<T>::operator=(Vector<T>&& other) noexcept
{
    this->destroy();
    this->rn = other.rn;
    this->n = other.rn;
    this->mem = std::exchange(other.mem, nullptr);
    this->mem_len = other.mem_len;
    this->new_mem = other.new_mem;
    this->allocator = other.allocator;

    return *this;
}

template <typename T>
Vector<T>::~Vector()
{
    destroy();
}

template <typename T>
inline const gf::RingModN<T>& Vector<T>::get_gf(void) const
{
    return *rn;
}

template <typename T>
inline int Vector<T>::get_n(void) const
{
    return this->n;
}

template <typename T>
inline int Vector<T>::get_mem_len(void) const
{
    return this->mem_len;
}

template <typename T>
void Vector<T>::zero_fill(void)
{
    int i;

    for (i = 0; i < n; i++)
        set(i, 0);
}

template <typename T>
void Vector<T>::fill(T val)
{
    for (auto i = 0; i < n; i++) {
        mem[i] = val;
    }
}

template <typename T>
inline void Vector<T>::set(int i, T val)
{
    assert(i >= 0 && i < n);

    mem[i] = val;
}

template <typename T>
inline const T& Vector<T>::get(int i) const
{
    assert(i >= 0 && i < n);

    return mem[i];
}

template <typename T>
inline T* Vector<T>::get_mem() const
{
    return mem;
}

template <typename T>
inline void Vector<T>::set_mem(T* mem, int mem_len)
{
    destroy();
    new_mem = false;
    this->mem = mem;
    this->mem_len = mem_len;
}

/** Multiplication of a vector by a scalar
 *
 * @param[in] scalar a number
 */
template <typename T>
void Vector<T>::mul_scalar(T scalar)
{
    for (int i = 0; i < n; i++)
        set(i, rn->mul(get(i), scalar));
}

/** Multiplication of i<sup>th</sup> element of a vector by a scalar = beta^i
 *
 * @param[in] beta a number
 */
template <typename T>
void Vector<T>::mul_beta(T beta)
{
    T coef = beta;
    for (int i = 1; i < n; i++) {
        mem[i] = rn->mul(mem[i], coef);
        coef = rn->mul(coef, beta);
    }
}

/** Entrywise product
 *
 * @param[in] v a vector
 */
template <typename T>
void Vector<T>::hadamard_mul(Vector<T>* v)
{
    assert(n == v->get_n());
    T* dest = mem;
    T* src = v->get_mem();
    rn->hadamard_mul(n, dest, src);
}

template <typename T>
void Vector<T>::add(Vector<T>* v)
{
    assert(n == v->get_n());

    T* src = v->get_mem();
    for (int i = 0; i < n; i++)
        mem[i] = rn->add(mem[i], src[i]);
}

template <typename T>
void Vector<T>::add(Vector<T>* v, int offset)
{
    assert(n >= v->get_n() + offset);

    T* src = v->get_mem();
    T* dest = mem + offset;

    for (int i = 0; i < v->get_n(); i++)
        dest[i] = rn->add(dest[i], src[i]);
}

template <typename T>
void Vector<T>::add_mutual(Vector<T>* v)
{
    int len = v->get_n();
    assert(n >= len);
    T* src = v->get_mem();
    T* dest = this->mem;
    for (int i = 0; i < len; i++)
        dest[i] = rn->add(dest[i], src[i]);
}

template <typename T>
void Vector<T>::add_mutual(Vector<T>* v, int offset)
{
    int len = v->get_n();
    assert(len == 0 || n - offset >= len);
    T* src = v->get_mem();
    T* dest = this->mem + offset;
    for (int i = 0; i < len; i++)
        dest[i] = rn->add(dest[i], src[i]);
}

template <typename T>
void Vector<T>::add_mutual(Vector<T>* v, int offset, int len)
{
    assert(len == 0 || n - offset >= len);
    assert(v->get_n() >= len);
    T* src = v->get_mem();
    T* dest = this->mem + offset;
    for (int i = 0; i < len; i++)
        dest[i] = rn->add(dest[i], src[i]);
}

template <typename T>
void Vector<T>::copy(Vector<T>* v)
{
    assert(v->get_mem_len() <= this->mem_len);
    std::copy_n(v->get_mem(), v->get_mem_len(), this->mem);
}

template <typename T>
void Vector<T>::copy(Vector<T>* v, int n)
{
    assert(n <= this->mem_len);
    int v_mem_len = v->get_mem_len();
    if (v_mem_len >= n)
        std::copy_n(v->get_mem(), n, this->mem);
    else {
        std::copy_n(v->get_mem(), v_mem_len, this->mem);
        std::memset(this->mem + v_mem_len, 0, sizeof(T) * (n - v_mem_len));
    }
}

template <typename T>
void Vector<T>::copy(Vector<T>* v, int n, int offset)
{
    assert(n + offset <= this->mem_len);
    int v_mem_len = v->get_mem_len();
    T* dest = this->mem + offset;
    if (v_mem_len >= n)
        std::copy_n(v->get_mem(), n, dest);
    else {
        std::copy_n(v->get_mem(), v_mem_len, dest);
        std::memset(dest + v_mem_len, 0, sizeof(T) * (n - v_mem_len));
    }
}

template <typename T>
void Vector<T>::copy(Vector<T>* v, int n, int dest_offset, int src_offset)
{
    assert(n + dest_offset <= this->mem_len);
    int src_len = v->get_mem_len() - src_offset;
    T* dest = this->mem + dest_offset;
    T* src = v->get_mem() + src_offset;
    if (src_len >= n)
        std::copy_n(src, n, dest);
    else {
        std::copy_n(src, src_len, dest);
        std::memset(dest + src_len, 0, sizeof(T) * (n - src_len));
    }
}

template <typename T>
bool operator==(const Vector<T>& lhs, const Vector<T>& rhs)
{
    if (lhs.n != rhs.n) {
        return false;
    }
    for (int i = 0; i < lhs.n; i++) {
        if (lhs.get(i) != rhs.get(i)) {
            return false;
        }
    }
    return true;
}

template <typename T>
void Vector<T>::neg()
{
    for (int i = 0; i < this->n; i++)
        mem[i] = rn->neg(mem[i]);
}

template <typename T>
void Vector<T>::to_poly(Poly<T>* poly)
{
    poly->clear();
    for (int i = 0; i < this->n; i++) {
        poly->set(i, get(i));
    }
}

template <typename T>
void Vector<T>::sort()
{
    std::sort(mem, mem + n);
}

template <typename T>
void Vector<T>::swap(unsigned i, unsigned j)
{
    using std::swap;
    swap(mem[i], mem[j]);
}

template <typename T>
void Vector<T>::rand()
{
    // XXX this actually does not work because gf_ring->rand()
    // distribution should be:
    // 1) based upon T (and not uint32_t)
    // 2) please initialize "dis" in constructor (not every time)
    for (int i = 0; i < this->n; i++) {
        set(i, rn->rand());
    }
}

template <typename T>
void Vector<T>::dump(void) const
{
    std::cout << "( ";
    for (int i = 0; i < n; i++)
        std::cout << get(i) << " ";
    std::cout << ")\n";
}

} // namespace vec
} // namespace quadiron

#endif
