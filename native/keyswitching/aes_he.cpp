#include "aes_he.hpp"

CryptoBitset<128> AddRoundKey(CryptoBitset<128> const& currentBlock,
                              CryptoBitset<128> const& currentKeys)
{
    return currentBlock ^ currentKeys;
}

CryptoBitset<128> SubBytes(CryptoBitset<128> const& currentBlock)
{
    // divides the current block into 16 independent bytes
    std::vector<CryptoBitset<8>> blockByBytes = currentBlock.split<16>();
    BitEncryptionContext& ctxt = currentBlock.bit_encryption_context();

    // apply the AES SBOX on each independent byte
    for (auto& byte : blockByBytes)
        byte = Sbox_AES128.apply(ctxt, byte);

    return CryptoBitset<128>::move_and_join<8>(ctxt, blockByBytes);
}

CryptoBitset<128> InvSubBytes(CryptoBitset<128> const& currentBlock)
{
    std::array<std::future<CryptoBitset<8>>, 16> futurs;
    std::vector<CryptoBitset<8>> blockByBytes = currentBlock.split<16>();
    BitEncryptionContext& ctxt = currentBlock.bit_encryption_context();

    for (auto& byte : blockByBytes)
        byte = Sbox_AES128.reverse(ctxt, byte);

    return CryptoBitset<128>::move_and_join<8>(ctxt, blockByBytes);
}

CryptoBitset<128> SubBytesParallelv1(CryptoBitset<128> const& currentBlock)
{
    std::array<std::future<CryptoBitset<8>>, 16> futurs;
    std::vector<CryptoBitset<8>> blockByBytes = currentBlock.split<16>();
    BitEncryptionContext& ctxt = currentBlock.bit_encryption_context();

    std::function<CryptoBitset<8>(CryptoBitset<8> const&)> ApplySbox = 
    [](CryptoBitset<8> const& block) -> CryptoBitset<8> {
        return Sbox_AES128.apply(block.bit_encryption_context(), block);
    };

    #define NUM_THREADS 4
    #pragma omp parallel for num_threads(NUM_THREADS)
    for (unsigned i = 0; i < 16; i++) {
        blockByBytes[i] = Sbox_AES128.apply(blockByBytes[i].bit_encryption_context(), blockByBytes[i]);
    }
    /*
    for (unsigned i = 0; i < 4; i++) {
        ExecInParallel(
            ApplySbox, futurs[i*4  ], blockByBytes[i*4  ], 
            ApplySbox, futurs[i*4+1], blockByBytes[i*4+1],
            ApplySbox, futurs[i*4+2], blockByBytes[i*4+2],
            ApplySbox, futurs[i*4+3], blockByBytes[i*4+3]
        );
    }
    
    for (unsigned i = 0; i < 16; i++)
        blockByBytes[i] = futurs[i].get();*/

    return CryptoBitset<128>::move_and_join<8>(ctxt, blockByBytes);
}

CryptoBitset<128> SubBytesParallelv2(CryptoBitset<128> const& currentBlock)
{
    std::array<std::future<CryptoBitset<8>>, 16> futurs;
    std::vector<CryptoBitset<8>> blockByBytes = currentBlock.split<16>();

    auto f = [](CryptoBitset<8> const& block) {
        return Sbox_AES128.apply(
            block.bit_encryption_context(), block
        );
    };

    for (size_t i = 0; i < 16; i++)
        futurs[i] = std::async(std::launch::async, f, blockByBytes[i]);
    
    for (auto& ft : futurs) ft.wait();

    for (unsigned i = 0; i < 16; i++)
        blockByBytes[i] = futurs[i].get();

    return CryptoBitset<128>::move_and_join<8>(
        currentBlock.bit_encryption_context(),
        blockByBytes
    );
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
CryptoBitset<128> ShiftRows(CryptoBitset<128> const& currentBlock)
{
    std::vector<CryptoBitset<8>> blockBytes = currentBlock.split<16>();

    // Rotate first row 1 columns to right
    CryptoBitset<8> tmp = blockBytes[1];
    
    blockBytes[ 1] = blockBytes[ 5];
    blockBytes[ 5] = blockBytes[ 9];
    blockBytes[ 9] = blockBytes[13];
    blockBytes[13] = tmp;

    // Rotate second row 2 columns to right
    tmp = blockBytes[2];
    blockBytes[ 2] = blockBytes[10];
    blockBytes[10] = tmp;

    tmp = blockBytes[6];
    blockBytes[6] = blockBytes[14];
    blockBytes[14] = tmp;
  
    // Rotate third row 3 columns to right
    tmp = blockBytes[15];
    blockBytes[15] = blockBytes[11];
    blockBytes[11] = blockBytes[7];
    blockBytes[ 7] = blockBytes[3];
    blockBytes[ 3] = tmp;

    return CryptoBitset<128>::move_and_join<8>(blockBytes[0].bit_encryption_context(), 
                                      blockBytes);
}

CryptoBitset<128> InvShiftRows(CryptoBitset<128> const& currentBlock)
{
    std::vector<CryptoBitset<8>> blockBytes = currentBlock.split<16>();

    CryptoBitset<8> tmp = blockBytes[13];
    blockBytes[13] = blockBytes[ 9];
    blockBytes[ 9] = blockBytes[ 5];
    blockBytes[ 5] = blockBytes[ 1];
    blockBytes[ 1] = tmp;

    tmp = blockBytes[10];
    blockBytes[10] = blockBytes[2];
    blockBytes[ 2] = tmp;

    tmp = blockBytes[14];
    blockBytes[14] = blockBytes[6];
    blockBytes[ 6] = tmp;
  
    // Rotate third row 3 columns to right
    tmp = blockBytes[3];
    blockBytes[ 3] = blockBytes[ 7];
    blockBytes[ 7] = blockBytes[11];
    blockBytes[11] = blockBytes[15];
    blockBytes[15] = tmp;

    return CryptoBitset<128>::move_and_join<8>(blockBytes[0].bit_encryption_context(), 
                                      blockBytes);
}

// The round constant word array, round_const[i], contains the values given by  
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field 
// GF(2^8)
// Note that i starts at 1, not 0.
std::array<uint8_t, 255> round_const = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 
    0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 
    0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 
    0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 
    0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 
    0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 
    0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 
    0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

std::vector<CryptoBitset<128>> KeyExpansionParallel(CryptoBitset<128> const& AESKey)
{
    size_t key_size = 128;
    size_t Nk = key_size/32;
    size_t Nr = Nk+6;

    // This set represents the set of 128-bit keys used during the AES procedure
    // There are Nr+1 keys ; the first one of the set is the original key 
    std::vector<CryptoBitset<32>> expandedKey;
    expandedKey.reserve(4*(Nr+1));

    // Copy the first round key, which is the AES key itself
    // Original Key in the first C_i columns for i = 0, ..., Nk-1
    // with Nk = 4, 6 or 8 (for a key size of 128, 196 or 256-bit)
    std::vector<CryptoBitset<32>> v = AESKey.split<4>();
    unsigned long int i = v.size();

    //std::copy_n(std::make_move_iterator(v.begin()), v.size(),
    //    std::back_inserter(expandedKey));
    //v.erase(v.begin(), v.end());
    std::copy_n(v.begin(), v.size(),
                std::back_inserter(expandedKey));

    // Now, we can apply the algorithm:
    // for i >= Nk, C_i = D_i XOR C_i - (Nk - 1) with
    // (*) D_i = C_{i - 1} if Nk doesn't divide i
    // (*) D_i = SubWord(RotWord(C_i - 1)) XOR Rcst_{(i-1)/Nk} if Nk divides i
    while (i < (4 * (Nr+1)))
    {
        // load C_{i-1}
        CryptoBitset<32> tmpWord = expandedKey.back();
        std::vector<CryptoBitset<8>> test = tmpWord.split<4>();
        for (unsigned k = 0; k < 4; k++)
            std::cout << "C_{i-1} " << test[k].decrypt().to_ulong() << std::endl;
        std::cout << std::endl;
        if (i % Nk == 0) {
            // Rotates the 4 bytes of the double word to the right  
            // [a3,a2,a1,a0] becomes [a0,a3,a2,a1]
            CryptoBitset<32> rotatedWord = tmpWord.rotate_right(8);
            std::cout << "temp " << rotatedWord.decrypt().to_ulong() << std::endl;

            std::vector<CryptoBitset<8>> blockByBytes = rotatedWord.split<4>();
            std::cout << "temp array" << std::endl;
            for (unsigned i = 0; i < 4; i++)
              std::cout << blockByBytes[i].decrypt().to_ulong() << " " << std::endl; 
            std::cout << std::endl;

            // Apply the S-box to each of the four bytes to produce an output word
            auto f = [](CryptoBitset<8> const& block) {
                return Sbox_AES128.apply(
                    block.bit_encryption_context(), block
                );
            };

            std::future<CryptoBitset<8>> futurs[4];
    
            futurs[0] = std::async(std::launch::async, f, blockByBytes[0]);
            futurs[1] = std::async(std::launch::async, f, blockByBytes[1]);
            futurs[2] = std::async(std::launch::async, f, blockByBytes[2]);
            futurs[3] = std::async(std::launch::async, f, blockByBytes[3]);

            for (unsigned j = 0; j < 4; j++) {
                futurs[j].wait();
                blockByBytes[j] = futurs[j].get();
            }

            // On the eight first bit, we XOR with the 8-bit Round Const
            blockByBytes[0] = blockByBytes[0] ^ ClearBitset<8>(round_const[i/Nk]);

            std::vector<CryptoBitset<8>> tmpVector = { blockByBytes[0], blockByBytes[1], 
                                                       blockByBytes[2], blockByBytes[3] };

            tmpWord = CryptoBitset<32>::move_and_join<8>(blockByBytes[0].bit_encryption_context(),
                tmpVector
            );
        }
        // C_i = D_i XOR C_{i-Nk} avec D_i = C_{i-1}
        // C_i = C_{i-Nk} XOR D_i
        expandedKey.push_back(expandedKey[i-Nk] ^ tmpWord);
        i++;
    }

    std::vector<CryptoBitset<128>> finalizedKeys;
    std::vector<CryptoBitset<32>> acc_vec;
    acc_vec.reserve(4);

    for (unsigned k = 0; k < 4*(Nr+1); k += 4) {
        std::copy(std::make_move_iterator(expandedKey.begin()), 
                  std::make_move_iterator(expandedKey.begin()+4),
                  std::back_inserter(acc_vec));

        expandedKey.erase(expandedKey.begin(), expandedKey.begin()+4);
        
        finalizedKeys.push_back(CryptoBitset<128>::move_and_join<32>(
            expandedKey[0].bit_encryption_context(), 
            acc_vec));
        acc_vec.clear();
    }

    return finalizedKeys;
}

#define Multiply HE_GF256_mul_circuit

// MixColumns function mixes the columns of the currentBlock
CryptoBitset<128> MixColumns(CryptoBitset<128> const& currentBlock)
{
    BitEncryptionContext& ctxt = currentBlock.bit_encryption_context();
    CryptoBitset<8> a(ctxt), b(ctxt), c(ctxt), d(ctxt);
    std::vector<CryptoBitset<8>> splittedBlock = currentBlock.split<16>();
    
    ClearBitset<8> cst1(0x01), cst2(0x02), cst3(0x03);

    for (unsigned i = 0; i < 4; i++) {    
        a = splittedBlock[i*4  ];
        b = splittedBlock[i*4+1];
        c = splittedBlock[i*4+2];
        d = splittedBlock[i*4+3];

        splittedBlock[i*4  ] = Multiply(a, cst2) ^ Multiply(b, cst3) ^ Multiply(c, cst1) ^ Multiply(d, cst1);
        splittedBlock[i*4+1] = Multiply(a, cst1) ^ Multiply(b, cst2) ^ Multiply(c, cst3) ^ Multiply(d, cst1);
        splittedBlock[i*4+2] = Multiply(a, cst1) ^ Multiply(b, cst1) ^ Multiply(c, cst2) ^ Multiply(d, cst3);
        splittedBlock[i*4+3] = Multiply(a, cst3) ^ Multiply(b, cst1) ^ Multiply(c, cst1) ^ Multiply(d, cst2);
    }

    return CryptoBitset<128>::move_and_join<8>(ctxt, splittedBlock);
}

CryptoBitset<128> InvMixColumns(CryptoBitset<128> const& currentBlock)
{
    BitEncryptionContext& ctxt = currentBlock.bit_encryption_context();
    CryptoBitset<8> a(ctxt), b(ctxt), c(ctxt), d(ctxt);
    std::vector<CryptoBitset<8>> splittedBlock = currentBlock.split<16>();

    ClearBitset<8> cst9(0x09), cste(0x0e), cstb(0x0b), cstd(0x0d);

    for (unsigned i = 0; i < 4; i++)
    {    
        a = splittedBlock[i*4  ];
        b = splittedBlock[i*4+1];
        c = splittedBlock[i*4+2];
        d = splittedBlock[i*4+3];

        splittedBlock[i*4  ] = Multiply(a, cste) ^ Multiply(b, cstb) ^ Multiply(c, cstd) ^ Multiply(d, cst9);
        splittedBlock[i*4+1] = Multiply(a, cst9) ^ Multiply(b, cste) ^ Multiply(c, cstb) ^ Multiply(d, cstd);
        splittedBlock[i*4+2] = Multiply(a, cstd) ^ Multiply(b, cst9) ^ Multiply(c, cste) ^ Multiply(d, cstb);
        splittedBlock[i*4+3] = Multiply(a, cstb) ^ Multiply(b, cstd) ^ Multiply(c, cst9) ^ Multiply(d, cste);
    }

    return CryptoBitset<128>::move_and_join<8>(ctxt, splittedBlock);
}

#undef Multiply
/*
void f()
{
    t0 = x0 ^ x8
t1 = x16 ^ x24
t2 = x1 ^ x9
t3 = x17 ^ x25
t4 = x2 ^ x10
t5 = x18 ^ x26
t6 = x3 ^ x11
t7 = x19 ^ x27
t8 = x4 ^ x12
t9 = x20 ^ x28
t10 = x5 ^ x13
t11 = x21 ^ x29
t12 = x6 ^ x14
t13 = x22 ^ x30
t14 = x23 ^ x31
t15 = x7 ^ x15
t16 = x8 ^ t1
y0 = t15 ^ t16
t17 = x7 ^ x23

t18 = x24 ^ t0
y16 = t14 ^ t18
t19 = t1 ^ y16
y24 = t17 ^ t19
t20 = x27 ^ t14
t21 = t0 ^ y0
y8 = t17 ^ t21
t22 = t5 ^ t20
y19 = t6 ^ t22
t23 = x11 ^ t15
t24 = t7 ^ t23
y3 = t4 ^ t24
t25 = x2 ^ x18
t26 = t17 ^ t25
t27 = t9 ^ t23
t28 = t8 ^ t20
t29 = x10 ^ t2
y2 = t5 ^ t29
t30 = x26 ^ t3

y18 = t4 ^ t30
t31 = x9 ^ x25
t32 = t25 ^ t31
y10 = t30 ^ t32
y26 = t29 ^ t32
t33 = x1 ^ t18
t34 = x30 ^ t11
y22 = t12 ^ t34
t35 = x14 ^ t13
y6 = t10 ^ t35
t36 = x5 ^ x21
t37 = x30 ^ t17
t38 = x17 ^ t16
t39 = x13 ^ t8
y5 = t11 ^ t39
t40 = x12 ^ t36
t41 = x29 ^ t9
y21 = t10 ^ t41
t42 = x28 ^ t40

y13 = t41 ^ t42
y29 = t39 ^ t42
t43 = x15 ^ t12
y7 = t14 ^ t43
t44 = x14 ^ t37
y31 = t43 ^ t44
t45 = x31 ^ t13
y15 = t44 ^ t45
y23 = t15 ^ t45
t46 = t12 ^ t36
y14 = y6 ^ t46
t47 = t31 ^ t33
y17 = t19 ^ t47
t48 = t6 ^ y3
y11 = t26 ^ t48
t49 = t2 ^ t38
y25 = y24 ^ t49
t50 = t7 ^ y19
y27 = t26 ^ t50

t51 = x22 ^ t46
y30 = t11 ^ t51
t52 = x19 ^ t28
y20 = x28 ^ t52
t53 = x3 ^ t27
y4 = x12 ^ t53
t54 = t3 ^ t33
y9 = y8 ^ t54
t55 = t21 ^ t31
y1 = t38 ^ t55
t56 = x4 ^ t17
t57 = x19 ^ t56
y12 = t27 ^ t57
t58 = x3 ^ t28
t59 = t17 ^ t58
y28 = x20 ^ t59
}*/