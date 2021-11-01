#ifndef __OUTERPRODUCT_HPP__
#define __OUTERPRODUCT_HPP__

#include "examples.h"

using namespace seal;

std::vector<Ciphertext> OuterProductV1(Evaluator              & eval,
                                       std::vector<Ciphertext>& vec1,
                                       std::vector<Ciphertext>& vec2);

// We still need to return a container of Ciphertext
std::vector<Ciphertext> OuterProductV2(EncryptionParameters params,
                                       Evaluator       &    eval,
                                       const Ciphertext&    vec1,
                                       const Ciphertext&    vec2,
                                       GaloisKeys      &    gk,
                                       size_t               vec1Size,
                                       size_t               vec2Size = 0ULL);

#endif