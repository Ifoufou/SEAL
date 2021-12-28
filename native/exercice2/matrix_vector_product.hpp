#ifndef __MATRIX_VECTOR_PRODUCT_HPP__
#define __MATRIX_VECTOR_PRODUCT_HPP__

#include "examples.h"

using namespace seal;

// Using the Inner product
std::vector<Ciphertext> matrixVectorProduct(EncryptionParameters& parms,
                                            Evaluator  & eval,
                                            const std::vector<Ciphertext>& matrix, 
                                            const Ciphertext& vec,
                                            GaloisKeys & gk,
                                            RelinKeys  & rk,
                                            size_t NbElem);

// Let's denote the dimensions of matrix as (m,n) and the dimensions of vec as
// (n,1). Given N, the poly_mod_degree of eval/matrix/vec, we assume that 
// m <= N/2. This hypothesis allow us to return directly a batched vector.
Ciphertext squareMatrixVectorProduct(EncryptionParameters& params,
                                     Evaluator& eval,
                                     const std::vector<Ciphertext>& cyclicDiagsMatrix,
                                     const Ciphertext& vec,
                                     size_t realVectorSize,
                                     GaloisKeys& gk);

#endif 
