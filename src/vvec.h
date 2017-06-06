/* -*- mode: c++ -*- */
#pragma once

/** 
 * Virtual vector that returns 0 beyond managed vector length
 */
template<typename T>
class VVec : public Vec<T>
{
 private:
  Vec<T> *vec;
 public:
  int n;
  VVec(Vec<T> *vec, int n);
  T get(int i);
};

template <typename T>
VVec<T>::VVec(Vec<T> *vec, int n) : Vec<T>(NULL, 0)
{
  this->vec = vec;
  this->n = n;
}

template <typename T>
T VVec<T>::get(int i)
{
  assert(i >= 0 && i < n);

  return (i < vec->n) ? vec->get(i) : 0;
}