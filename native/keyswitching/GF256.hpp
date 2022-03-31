#include <iostream>
#include "encryptionlayer.hpp"


uint8_t GFM_mul(uint8_t b0, uint8_t b1, unsigned int M);

// Implementation of the multiplication operation performed on two elements
// of the galois field GF(2^8) as a boolean circuit
//
// See: http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
uint8_t GF256_mul_circuit(uint8_t a, uint8_t b);


CryptoBitset<8> HE_GF256_mul(CryptoBitset<8> b0, CryptoBitset<8> b1);

CryptoBitset<8> HE_GF256_mul_circuit(const CryptoBitset<8>& a, const CryptoBitset<8>& b);
CryptoBitset<8> HE_GF256_mul_circuit(const CryptoBitset<8>& a, const ClearBitset <8>& b);