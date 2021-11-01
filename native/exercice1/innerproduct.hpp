#ifndef __INNERPRODUCT_HPP__
#define __INNERPRODUCT_HPP__

#include "examples.h"

using namespace seal;

// Recall that SEAL works only with modular arithmetic. Hence, the values of 
// all coefficients V_i of a given vector are bounded between [-N/2-1, N/2]
// where N is the ...  (TODO: end this comment)

// This is the "naive" implementation of the inner product within the SEAL API.
// Each element of the vectors are encrypted in a different cipher. Thus, we can
// represent them as a std::vector (container) of seal::Ciphertext !
Ciphertext InnerProductV1(Evaluator& eval,
                          const std::vector<Ciphertext>& vec1,
                          const std::vector<Ciphertext>& vec2);

// In this implementation, we saw vectors as one atomic element, i.e. in a SIMD 
// manner. Values can't be extracted without a decryption stage! This is done 
// by using the BatchEncoder of BFV. As the previous version, this function is
// intended to work on the server, and the client is supposed to send informations
// about the (batched) ciphers like the number of values in the vectors, the 
// galois keys, the relinearization keys, and at least the EncryptionParameters).
// To sum up, all informations that are not related to the decryption of the ciphers!
// The evaluator could be deduced from the enc. parameters but for code factorization 
// purposes, we added a reference to it in the arguments list.
Ciphertext InnerProductV2(EncryptionParameters& parms,
                          Evaluator  & eval,
                          const Ciphertext& vec1, 
                          const Ciphertext& vec2,
                          GaloisKeys & gk,
                          RelinKeys  & rk,
                          size_t NbElem);

#endif 