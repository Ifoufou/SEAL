#include <future>

#include "encryptionlayer.hpp"
#include "GF256.hpp"
#include "sbox.hpp"
#include "omp.h"

// Enumerations of the differents AES Mode (128, 192 and 256)
enum AES_Mode : size_t {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
};

extern std::array<uint8_t, 255> round_const;

// Homomorphic Evaluation of an AES Key-switching on a 128-bit block
// This function switches the keys of a cipher (from k0 to k1)
// The parameter "block_enc" is assumed to be encrypted with k0 
template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Keyswitching(CryptoBitset<128> const& block_enc,
                                      CryptoBitset<key_size> const& k0,
                                      CryptoBitset<key_size> const& k1);

// Homomorphic Evaluation of the AES encryption function on a 128-bit block
// It is the main function that encrypts homomorphically plaintexts
template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Encrypt(CryptoBitset<128> const& plainBlock,
                                 std::vector<CryptoBitset<128>> const& currentKeys);

// Homomorphic Evaluation of the AES decryption function 
// It is the main function that decrypts homomorphically ciphertexts
template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Decrypt(CryptoBitset<128> const& cipherBlock,
                                 std::vector<CryptoBitset<128>> const& currentKeys);

template<AES_Mode key_size>
std::vector<CryptoBitset<128>> KeyExpansion(CryptoBitset<key_size> const& AESKey);

CryptoBitset<128> AddRoundKey(CryptoBitset<128> const& plainBlock,
                              CryptoBitset<128> const& currentKeys);

CryptoBitset<128> SubBytes(CryptoBitset<128> const& currentBlock);
CryptoBitset<128> SubBytesParallelv1(CryptoBitset<128> const& currentBlock);
CryptoBitset<128> SubBytesParallelv2(CryptoBitset<128> const& currentBlock);
CryptoBitset<128> InvSubBytes(CryptoBitset<128> const& currentBlock);

CryptoBitset<128> ShiftRows(CryptoBitset<128> const& currentBlock);
CryptoBitset<128> InvShiftRows(CryptoBitset<128> const& currentBlock);

CryptoBitset<128> MixColumns   (CryptoBitset<128> const& currentBlock);
CryptoBitset<128> InvMixColumns(CryptoBitset<128> const& currentBlock);

std::vector<CryptoBitset<128>> KeyExpansionParallel(CryptoBitset<128> const& AESKey);

// Template Definitions
//
template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Keyswitching(CryptoBitset<128> const& block_enc_with_k0,
                                      CryptoBitset<key_size> const& k0,
                                      CryptoBitset<key_size> const& k1)
{
    std::vector<CryptoBitset<128>> keys_derived_k0 = KeyExpansion<key_size>(k0);
    std::vector<CryptoBitset<128>> keys_derived_k1 = KeyExpansion<key_size>(k1);
    CryptoBitset<128> he_plain_data = HE_AES_Decrypt<key_size>(block_enc_with_k0, keys_derived_k0);
    he_plain_data.refresh();
    return HE_AES_Encrypt<key_size>(he_plain_data, keys_derived_k1);
}

template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Encrypt(CryptoBitset<128> const& plainBlock,
                                 std::vector<CryptoBitset<128>> const& currentKeys)
{
    // There is Nr rounds
    unsigned int round = 0;
    unsigned int Nr = key_size / 32 + 6;
    assert(Nr+1 == currentKeys.size());

    // Add the first round key to the currentBlock before starting the rounds
    CryptoBitset<128> currentBlock = AddRoundKey(plainBlock, currentKeys[round]);

    // The first Nr-1 rounds are identical: they are 
    // executed in the loop below
    for (round = 1; round < Nr; round++) {
        std::cout << "Round " << round << std::endl;
        currentBlock = SubBytes(currentBlock);
        currentBlock.refresh();
        currentBlock = ShiftRows(currentBlock);
        currentBlock = MixColumns(currentBlock);
        currentBlock.refresh();
        currentBlock = AddRoundKey(currentBlock, currentKeys[round]);
    }

    // The last round is given below:
    // (Note that MixColumns isn't in the last round)
    currentBlock = SubBytes(currentBlock);
    currentBlock = ShiftRows(currentBlock);
    return AddRoundKey(currentBlock, currentKeys[Nr]);
}

template<AES_Mode key_size>
CryptoBitset<128> HE_AES_Decrypt(CryptoBitset<128> const& cipherBlock,
                                 std::vector<CryptoBitset<128>> const& currentKeys)
{
    unsigned int round = 0;
    unsigned int Nr = key_size / 32 + 6;
    assert(Nr+1 == currentKeys.size());

    CryptoBitset<128> currentBlock = AddRoundKey(cipherBlock, currentKeys[Nr]);

    for (round = Nr-1; round > 0; round--) {
        std::cout << "Round " << round << std::endl;
        currentBlock = InvShiftRows(currentBlock);
        currentBlock = InvSubBytes(currentBlock);
        currentBlock.refresh();
        currentBlock = AddRoundKey(currentBlock, currentKeys[round]);
        currentBlock = InvMixColumns(currentBlock);
        currentBlock.refresh();
    }

    currentBlock = InvShiftRows(currentBlock);
    currentBlock = InvSubBytes(currentBlock);
    return AddRoundKey(currentBlock, currentKeys[0]);
}

template<AES_Mode key_size>
std::vector<CryptoBitset<128>> KeyExpansion(CryptoBitset<key_size> const& AESKey)
{
    const unsigned Nk = key_size / 32;
    const unsigned Nr = Nk + 6;

    // This set represents the set of 128-bit keys used during the AES procedure
    // There are Nr+1 keys (as AddRoundKey is called Nr+1 times)
    // The first one of the set is the original key
    std::vector<CryptoBitset<32>> expandedKey;
    expandedKey.reserve(4*(Nr+1));

    std::vector<CryptoBitset<32>> v = AESKey.template split<Nk>();
    unsigned long int i = v.size();

    // Copy the first round key, which is the AES key itself:
    // Original Key in the first C_i columns for i = 0, ..., Nk-1
    // with Nk = 4, 6 or 8 (for a key size of 128, 192 or 256-bit)
    std::copy_n(v.begin(), v.size(),
                std::back_inserter(expandedKey));

    // NOTE: (move semantic)
    //std::copy_n(std::make_move_iterator(v.begin()), v.size(),
    //    std::back_inserter(expandedKey));
    //v.erase(v.begin(), v.end());
    
    auto f = [](CryptoBitset<8> const& block) {
        return Sbox_AES128.apply(
            block.bit_encryption_context(), block
        );
    };

    // Now, we can apply the algorithm:
    // for i >= Nk, C_i = D_i XOR C_{i-Nk} with
    // (*) D_i = SubWord(RotWord(C_{i-1})) XOR Rcst_{(i)/Nk} if Nk divides i
    // (*) D_i = SubWord(C_{i-1}) if i % Nk == 4 and AES-256
    // (*) D_i = C_{i-1} otherwise
    while (i < (4 * (Nr+1)))
    {
        // load C_{i-1}
        CryptoBitset<32> tmpWord = expandedKey.back();

        // D_i = SubWord(RotWord(C_{i-1})) XOR Rcst_{(i)/Nk}
        if (i % Nk == 0) {
            // Rotates the 4 bytes of the double word to the right  
            // [a3,a2,a1,a0] becomes [a0,a3,a2,a1] where a3 is the MSB
            // If we take not a3 in first position but a0 (the LSB), we 
            // have [a0,a1,a2,a3] and thus, we need to make a left 
            // rotation this time to ensure that the LSB becomes the MSB.
            // This is why the AES Standard says the we must perform a 
            // left rotation here and we're making a right one.
            CryptoBitset<32> rotatedWord = tmpWord.rotate_right(8);
            std::vector<CryptoBitset<8>> blockByBytes = rotatedWord.split<4>();

            // Apply the S-box to each of the four bytes to produce an output word
            blockByBytes[0] = f(blockByBytes[0]);
            blockByBytes[1] = f(blockByBytes[1]);
            blockByBytes[2] = f(blockByBytes[2]);
            blockByBytes[3] = f(blockByBytes[3]);

            // On the eight first bit, we XOR with the 8-bit Round Const
            // As we use the BFV/BGV encryption scheme, we can mix encrypted
            // and plain data (constant value, here the round_const[i/Nk]) in 
            // the calculations:  
            blockByBytes[0] = blockByBytes[0] ^ ClearBitset<8>(round_const[i/Nk]);

            std::vector<CryptoBitset<8>> tmpVector = { blockByBytes[0], blockByBytes[1], 
                                                       blockByBytes[2], blockByBytes[3] };
            
            // merge the 4x8-bit words into a 32-bit one      
            tmpWord = CryptoBitset<32>::move_and_join<8>(
                blockByBytes[0].bit_encryption_context(),
                tmpVector
            );
        }
        // (AES-256) Nk = 8
        else if (Nk > 6 && i % Nk == 4)
        {
            std::vector<CryptoBitset<8>> blockByBytes = tmpWord.split<4>();
            
            blockByBytes[0] = f(blockByBytes[0]);
            blockByBytes[1] = f(blockByBytes[1]);
            blockByBytes[2] = f(blockByBytes[2]);
            blockByBytes[3] = f(blockByBytes[3]);

            std::vector<CryptoBitset<8>> tmpVector = { blockByBytes[0], blockByBytes[1], 
                                                       blockByBytes[2], blockByBytes[3] };
            
            // merge the 4x8-bit words into a 32-bit one
            tmpWord = CryptoBitset<32>::move_and_join<8>(
                blockByBytes[0].bit_encryption_context(),
                tmpVector
            );
        }

        // C_i = C_{i-Nk} XOR D_i
        expandedKey.push_back(expandedKey[i-Nk] ^ tmpWord);
        expandedKey.back().refresh();
        i++;
    }

    std::vector<CryptoBitset<128>> finalizedKeys;
    std::vector<CryptoBitset<32>>  acc_vec;
    acc_vec.reserve(4);

    // Merge each group of 4x32-bit words in full 128-bit key
    // The resulted keys will be in finalizedKeys
    for (unsigned k = 0; k < 4*(Nr+1); k += 4) {
        // move the content (into the accumulator vector) as we don't care
        // about keeping the content
        std::copy(std::make_move_iterator(expandedKey.begin()), 
                  std::make_move_iterator(expandedKey.begin()+4),
                  std::back_inserter(acc_vec));

        // erase the previously moved keys
        expandedKey.erase(expandedKey.begin(), expandedKey.begin()+4);
        
        // join the 4x32-bit keys into one 128-bit bitset 
        finalizedKeys.push_back(CryptoBitset<128>::move_and_join<32>(
            expandedKey[0].bit_encryption_context(), 
            acc_vec));
        
        // clear the accumulator vector
        acc_vec.clear();
    }

    return finalizedKeys;
}