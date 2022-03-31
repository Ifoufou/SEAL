#include "GF256.hpp"

uint8_t GFM_mul(uint8_t b0, uint8_t b1, unsigned int M)
{
    unsigned product = 0;
    for (unsigned i = 0; i < 8; i++) {
        product <<= 1;
        // if the 8th bit is one
        if (product & 0x100)
            product ^= M;
        if (b0 & 0x80u)
            product ^= b1;
        b0 <<= 1;
    }
    return static_cast<uint8_t>(product);
}

CryptoBitset<8> HE_GF256_mul(CryptoBitset<8> b0, CryptoBitset<8> b1)
{
    BitEncryptionContext& ctxt = b0.bit_encryption_context();
    assert(&ctxt == &b1.bit_encryption_context());

    // Express the order of the Galois field we are using
    // "0x100" means 2^8
    ClearBitset<16> order(0x100);
    // Most significant index (7th => 0x80) 
    ClearBitset <8>  MSIndex(0x80u);
    // Irreducible polynome used when performing the multiplication
    // All results obtained are modulo this polynome
    // This particular polynome is the AES one, i.e. 
    // x^8 + x^4 + x^3 + x + 1 (0x11b)
    ClearBitset <16> polyPrimitive(0x11b);
    CryptoBitset<16> product(ctxt);

    for (unsigned char i = 0; i < 8; i++) 
    {
        product <<= 1;
        
        // Recall that in FHE, we can simulate a "if" statement:
        // if c then x = a else x = b
        // <=>
        // x = (c AND a) XOR ((NOT c) AND b)

        // The following "if" statement:
        //      if (product & order)
        //          product ^= polyPrimitive;
        // can thus be extended as:
        //      if (product & order)
        //          product ^= polyPrimitive;
        //      else
        //          product  = product;
        // where all path are explicit (the "do nothing" has to be explicit). 
        // This gives us the 2 following lines:
        CryptoBitset<16> cond = product & order;
        // std::cout << cond.decrypt() << std::endl;
        product = (cond & (product ^ polyPrimitive)) ^ ((! cond) & product);
        // std::cout << product.decrypt() << std::endl;

        cond = CryptoBitset<16>(b0 & MSIndex);
        product = (cond & (product ^ b1)) ^ ((!cond) & product);
        // product.refresh();
        b0 <<= 1;
    }

    std::vector<CryptoBitset<8>> products = product.split<2>();
    // return the low part of the bitset
    return products[0];
}

uint8_t GF256_mul_circuit(uint8_t a, uint8_t b)
{
    // input polynomials are: A0 + A1*X + A2*X^2 + ... + A7*X^7 
    //                        B0 + B1*X + B2*X^2 + ... + B7*X^7
    // output polynomial is:  C0 + C1*X + C2*X^2 + ... + C7*X^7
    uint8_t A0 = a & 0b1;
    uint8_t A1 = (a >> 1) & 0b1;
    uint8_t A2 = (a >> 2) & 0b1;
    uint8_t A3 = (a >> 3) & 0b1;
    uint8_t A4 = (a >> 4) & 0b1;
    uint8_t A5 = (a >> 5) & 0b1;
    uint8_t A6 = (a >> 6) & 0b1;
    uint8_t A7 = (a >> 7) & 0b1;

    uint8_t B0 = b & 0b1;
    uint8_t B1 = (b >> 1) & 0b1;
    uint8_t B2 = (b >> 2) & 0b1;
    uint8_t B3 = (b >> 3) & 0b1;
    uint8_t B4 = (b >> 4) & 0b1;
    uint8_t B5 = (b >> 5) & 0b1;
    uint8_t B6 = (b >> 6) & 0b1;
    uint8_t B7 = (b >> 7) & 0b1;

    #define AND(T0, T1, T2) const uint8_t T0 = T1 & T2
    #define XOR(T0, T1, T2) const uint8_t T0 = T1 ^ T2
    #define ASSIGN(T0, T1)  const uint8_t T0 = T1

    AND(T1, A0, B0);
    AND(T2, A0, B1);
    AND(T3, A1, B0);
    AND(T4, A0, B2);
    AND(T5, A1, B1);
    AND(T6, A2, B0);
    AND(T7, A0, B3);
    AND(T8, A1, B2);
    AND(T9, A2, B1);
    AND(T10, A3, B0);
    AND(T11, A1, B3);
    AND(T12, A2, B2);
    AND(T13, A3, B1);
    AND(T14, A2, B3);
    AND(T15, A3, B2);
    AND(T16, A3, B3);
    AND(T17, A4, B4);
    AND(T18, A4, B5);
    AND(T19, A5, B4);
    AND(T20, A4, B6);
    AND(T21, A5, B5);
    AND(T22, A6, B4);
    AND(T23, A4, B7);
    AND(T24, A5, B6);
    AND(T25, A6, B5);
    AND(T26, A7, B4);
    AND(T27, A5, B7);
    AND(T28, A6, B6);
    AND(T29, A7, B5);
    AND(T30, A6, B7);
    AND(T31, A7, B6);
    AND(T32, A7, B7);

    XOR(T33, A0, A4);
    XOR(T34, A1, A5);
    XOR(T35, A2, A6);
    XOR(T36, A3, A7);
    XOR(T37, B0, B4);
    XOR(T38, B1, B5);
    XOR(T39, B2, B6);
    XOR(T40, B3, B7);

    AND(T41, T40, T36);
    AND(T42, T40, T35);
    AND(T43, T40, T34);
    AND(T44, T40, T33);
    AND(T45, T39, T36);
    AND(T46, T39, T35);
    AND(T47, T39, T34);
    AND(T48, T39, T33);
    AND(T49, T38, T36);
    AND(T50, T38, T35);
    AND(T51, T38, T34);
    AND(T52, T38, T33);
    AND(T53, T37, T36);
    AND(T54, T37, T35);
    AND(T55, T37, T34);
    AND(T56, T37, T33);

    XOR(T57, T2, T3);
    XOR(T58, T4, T5);
    XOR(T59, T6, T32);
    XOR(T60, T7, T8);
    XOR(T61, T9, T10);
    XOR(T62, T60, T61);
    XOR(T63, T11, T12);
    XOR(T64, T13, T63);
    XOR(T65, T14, T15);
    XOR(T66, T18, T19);
    XOR(T67, T20, T21);
    XOR(T68, T22, T67);
    XOR(T69, T23, T24);
    XOR(T70, T25, T26);
    XOR(T71, T69, T70);
    XOR(T72, T27, T28);
    XOR(T73, T29, T32);
    XOR(T74, T30, T31);
    XOR(T75, T52, T55);
    XOR(T76, T48, T51);
    XOR(T77, T54, T76);
    XOR(T78, T44, T47);
    XOR(T79, T50, T53);
    XOR(T80, T78, T79);
    XOR(T81, T43, T46);
    XOR(T82, T49, T81);
    XOR(T83, T42, T45);
    XOR(T84, T71, T74);
    XOR(T85, T41, T16);
    XOR(T86, T85, T68);
    XOR(T87, T66, T65);
    XOR(T88, T83, T87);
    XOR(T89, T58, T59);
    XOR(T90, T72, T73);
    XOR(T91, T74, T17);
    XOR(T92, T64, T91);
    XOR(T93, T82, T92);
    XOR(T94, T80, T62);
    XOR(T95, T94, T90);
    ASSIGN(C7, T95);
    XOR(T96, T41, T77);
    XOR(T97, T84, T89);
    XOR(T98, T96, T97);
    ASSIGN(C6, T98);
    XOR(T99, T57, T74);
    XOR(T100, T83, T75);
    XOR(T101, T86, T90);
    XOR(T102, T99, T100);
    XOR(T103, T101, T102);
    ASSIGN(C5, T103);
    XOR(T104, T1, T56);
    XOR(T105, T90, T104);
    XOR(T106, T82, T84);
    XOR(T107, T88, T105);
    XOR(T108, T106, T107);
    ASSIGN(C4, T108);
    XOR(T109, T71, T62);
    XOR(T110, T86, T109);
    XOR(T111, T110, T93);
    ASSIGN(C3, T111);
    XOR(T112, T86, T88);
    XOR(T113, T89, T112);
    ASSIGN(C2, T113);
    XOR(T114, T57, T32);
    XOR(T115, T114, T88);
    XOR(T116, T115, T93);
    ASSIGN(C1, T116);
    XOR(T117, T93, T1);
    ASSIGN(C0, T117);

    uint8_t res;
    res = (C7 << 7) | (C6 << 6) | (C5 << 5) | (C4 << 4) | (C3 << 3) | (C2 << 2) | (C1 << 1) | C0;

    #undef XOR
    #undef AND
    #undef ASSIGN

    return res;
}

CryptoBitset<8> HE_GF256_mul_circuit(const CryptoBitset<8>& a, const CryptoBitset<8> b)
{
    CryptoBitset<8> res(a);

    // input polynomials are: A0 + A1*X + A2*X^2 + ... + A7*X^7 
    //                        B0 + B1*X + B2*X^2 + ... + B7*X^7
    // output polynomial is:  C0 + C1*X + C2*X^2 + ... + C7*X^7
    const CryptoBit A0 = a[0];
    const CryptoBit A1 = a[1];
    const CryptoBit A2 = a[2];
    const CryptoBit A3 = a[3];
    const CryptoBit A4 = a[4];
    const CryptoBit A5 = a[5];
    const CryptoBit A6 = a[6];
    const CryptoBit A7 = a[7];

    const CryptoBit B0 = b[0];
    const CryptoBit B1 = b[1];
    const CryptoBit B2 = b[2];
    const CryptoBit B3 = b[3];
    const CryptoBit B4 = b[4];
    const CryptoBit B5 = b[5];
    const CryptoBit B6 = b[6];
    const CryptoBit B7 = b[7];

    #define AND(T0, T1, T2) const CryptoBit T0 = T1 & T2
    #define XOR(T0, T1, T2) const CryptoBit T0 = T1 ^ T2
    #define ASSIGN(T0, T1)  const CryptoBit T0 = T1

    AND(T1, A0, B0);
    AND(T2, A0, B1);
    AND(T3, A1, B0);
    AND(T4, A0, B2);
    AND(T5, A1, B1);
    AND(T6, A2, B0);
    AND(T7, A0, B3);
    AND(T8, A1, B2);
    AND(T9, A2, B1);
    AND(T10, A3, B0);
    AND(T11, A1, B3);
    AND(T12, A2, B2);
    AND(T13, A3, B1);
    AND(T14, A2, B3);
    AND(T15, A3, B2);
    AND(T16, A3, B3);
    AND(T17, A4, B4);
    AND(T18, A4, B5);
    AND(T19, A5, B4);
    AND(T20, A4, B6);
    AND(T21, A5, B5);
    AND(T22, A6, B4);
    AND(T23, A4, B7);
    AND(T24, A5, B6);
    AND(T25, A6, B5);
    AND(T26, A7, B4);
    AND(T27, A5, B7);
    AND(T28, A6, B6);
    AND(T29, A7, B5);
    AND(T30, A6, B7);
    AND(T31, A7, B6);
    AND(T32, A7, B7);

    XOR(T33, A0, A4);
    XOR(T34, A1, A5);
    XOR(T35, A2, A6);
    XOR(T36, A3, A7);
    XOR(T37, B0, B4);
    XOR(T38, B1, B5);
    XOR(T39, B2, B6);
    XOR(T40, B3, B7);

    AND(T41, T40, T36);
    AND(T42, T40, T35);
    AND(T43, T40, T34);
    AND(T44, T40, T33);
    AND(T45, T39, T36);
    AND(T46, T39, T35);
    AND(T47, T39, T34);
    AND(T48, T39, T33);
    AND(T49, T38, T36);
    AND(T50, T38, T35);
    AND(T51, T38, T34);
    AND(T52, T38, T33);
    AND(T53, T37, T36);
    AND(T54, T37, T35);
    AND(T55, T37, T34);
    AND(T56, T37, T33);

    XOR(T57, T2, T3);
    XOR(T58, T4, T5);
    XOR(T59, T6, T32);
    XOR(T60, T7, T8);
    XOR(T61, T9, T10);
    XOR(T62, T60, T61);
    XOR(T63, T11, T12);
    XOR(T64, T13, T63);
    XOR(T65, T14, T15);
    XOR(T66, T18, T19);
    XOR(T67, T20, T21);
    XOR(T68, T22, T67);
    XOR(T69, T23, T24);
    XOR(T70, T25, T26);
    XOR(T71, T69, T70);
    XOR(T72, T27, T28);
    XOR(T73, T29, T32);
    XOR(T74, T30, T31);
    XOR(T75, T52, T55);
    XOR(T76, T48, T51);
    XOR(T77, T54, T76);
    XOR(T78, T44, T47);
    XOR(T79, T50, T53);
    XOR(T80, T78, T79);
    XOR(T81, T43, T46);
    XOR(T82, T49, T81);
    XOR(T83, T42, T45);
    XOR(T84, T71, T74);
    XOR(T85, T41, T16);
    XOR(T86, T85, T68);
    XOR(T87, T66, T65);
    XOR(T88, T83, T87);
    XOR(T89, T58, T59);
    XOR(T90, T72, T73);
    XOR(T91, T74, T17);
    XOR(T92, T64, T91);
    XOR(T93, T82, T92);
    XOR(T94, T80, T62);
    XOR(T95, T94, T90);
    ASSIGN(C7, T95);
    XOR(T96, T41, T77);
    XOR(T97, T84, T89);
    XOR(T98, T96, T97);
    ASSIGN(C6, T98);
    XOR(T99, T57, T74);
    XOR(T100, T83, T75);
    XOR(T101, T86, T90);
    XOR(T102, T99, T100);
    XOR(T103, T101, T102);
    ASSIGN(C5, T103);
    XOR(T104, T1, T56);
    XOR(T105, T90, T104);
    XOR(T106, T82, T84);
    XOR(T107, T88, T105);
    XOR(T108, T106, T107);
    ASSIGN(C4, T108);
    XOR(T109, T71, T62);
    XOR(T110, T86, T109);
    XOR(T111, T110, T93);
    ASSIGN(C3, T111);
    XOR(T112, T86, T88);
    XOR(T113, T89, T112);
    ASSIGN(C2, T113);
    XOR(T114, T57, T32);
    XOR(T115, T114, T88);
    XOR(T116, T115, T93);
    ASSIGN(C1, T116);
    XOR(T117, T93, T1);
    ASSIGN(C0, T117);

    res[0] = C0;
    res[1] = C1;
    res[2] = C2;
    res[3] = C3;
    res[4] = C4;
    res[5] = C5;
    res[6] = C6;
    res[7] = C7;

    #undef XOR
    #undef AND
    #undef ASSIGN

    return res;
}

CryptoBitset<8> HE_GF256_mul_circuit(const CryptoBitset<8>& a, const ClearBitset<8>& b)
{
    CryptoBitset<8> res(a);
    // input polynomials are: A0 + A1*X + A2*X^2 + ... + A7*X^7 
    //                        B0 + B1*X + B2*X^2 + ... + B7*X^7
    // output polynomial is:  C0 + C1*X + C2*X^2 + ... + C7*X^7
    const CryptoBit A0 = a[0];
    const CryptoBit A1 = a[1];
    const CryptoBit A2 = a[2];
    const CryptoBit A3 = a[3];
    const CryptoBit A4 = a[4];
    const CryptoBit A5 = a[5];
    const CryptoBit A6 = a[6];
    const CryptoBit A7 = a[7];

    const ClearBit B0 = b[0];
    const ClearBit B1 = b[1];
    const ClearBit B2 = b[2];
    const ClearBit B3 = b[3];
    const ClearBit B4 = b[4];
    const ClearBit B5 = b[5];
    const ClearBit B6 = b[6];
    const ClearBit B7 = b[7];

    #define AND(T0, T1, T2) const CryptoBit T0 = T1 & T2
    #define XOR(T0, T1, T2) const CryptoBit T0 = T1 ^ T2
    #define ASSIGN(T0, T1)  const CryptoBit T0 = T1
    
    AND(T1, A0, B0);
    AND(T2, A0, B1);
    AND(T3, A1, B0);
    AND(T4, A0, B2);
    AND(T5, A1, B1);
    AND(T6, A2, B0);
    AND(T7, A0, B3);
    AND(T8, A1, B2);
    AND(T9, A2, B1);
    AND(T10, A3, B0);
    AND(T11, A1, B3);
    AND(T12, A2, B2);
    AND(T13, A3, B1);
    AND(T14, A2, B3);
    AND(T15, A3, B2);
    AND(T16, A3, B3);
    AND(T17, A4, B4);
    AND(T18, A4, B5);
    AND(T19, A5, B4);
    AND(T20, A4, B6);
    AND(T21, A5, B5);
    AND(T22, A6, B4);
    AND(T23, A4, B7);
    AND(T24, A5, B6);
    AND(T25, A6, B5);
    AND(T26, A7, B4);
    AND(T27, A5, B7);
    AND(T28, A6, B6);
    AND(T29, A7, B5);
    AND(T30, A6, B7);
    AND(T31, A7, B6);
    AND(T32, A7, B7);

    XOR(T33, A0, A4);
    XOR(T34, A1, A5);
    XOR(T35, A2, A6);
    XOR(T36, A3, A7);

    // A <- B AND C with B <- D XOR E where D, E are ClearBits
    // A <- (D XOR E) AND C
    // as we can't make operations on ClearBits directly, we have to rewrite it:
    // => A <- (C AND D) XOR (C AND E)
    // using the fact that logical conjunction distributes over exclusive or
    #define DISTR_AND_OVER_XOR(RES, XOR1_V, XOR2_V, AND_V) const CryptoBit RES = (AND_V & XOR1_V) ^ (AND_V & XOR2_V) 

    // AND(T41, T40, T36) with T40 = B3 XOR B7
    DISTR_AND_OVER_XOR(T41, B3, B7, T36);
    // AND(T42, T40, T35) with T40 = B3 XOR B7
    DISTR_AND_OVER_XOR(T42, B3, B7, T35);
    // AND(T43, T40, T34) with T40 = B3 XOR B7
    DISTR_AND_OVER_XOR(T43, B3, B7, T34);
    // AND(T44, T40, T33) with T40 = B3 XOR B7
    DISTR_AND_OVER_XOR(T44, B3, B7, T33);
    // AND(T45, T39, T36) with T39 = B2 XOR B6
    DISTR_AND_OVER_XOR(T45, B2, B6, T36);
    // AND(T46, T39, T35) with T39 = B2 XOR B6
    DISTR_AND_OVER_XOR(T46, B2, B6, T35);
    // AND(T47, T39, T34) with T39 = B2 XOR B6
    DISTR_AND_OVER_XOR(T47, B2, B6, T34);
    // AND(T48, T39, T33) with T39 = B2 XOR B6
    DISTR_AND_OVER_XOR(T48, B2, B6, T33);
    // AND(T49, T38, T36) with T38 = B1 XOR B5
    DISTR_AND_OVER_XOR(T49, B1, B5, T36);
    // AND(T50, T38, T35) with T38 = B1 XOR B5
    DISTR_AND_OVER_XOR(T50, B1, B5, T35);
    // AND(T51, T38, T34) with T38 = B1 XOR B5
    DISTR_AND_OVER_XOR(T51, B1, B5, T34);
    // AND(T52, T38, T33) with T38 = B1 XOR B5
    DISTR_AND_OVER_XOR(T52, B1, B5, T33);
    // AND(T53, T37, T36) with T37 = B0 XOR B4
    DISTR_AND_OVER_XOR(T53, B0, B4, T36);
    // AND(T54, T37, T35) with T37 = B0 XOR B4
    DISTR_AND_OVER_XOR(T54, B0, B4, T35);
    // AND(T55, T37, T34) with T37 = B0 XOR B4
    DISTR_AND_OVER_XOR(T55, B0, B4, T34);
    // AND(T56, T37, T33) with T37 = B0 XOR B4
    DISTR_AND_OVER_XOR(T56, B0, B4, T33);

    XOR(T57, T2, T3);
    XOR(T58, T4, T5);
    XOR(T59, T6, T32);
    XOR(T60, T7, T8);
    XOR(T61, T9, T10);
    XOR(T62, T60, T61);
    XOR(T63, T11, T12);
    XOR(T64, T13, T63);
    XOR(T65, T14, T15);
    XOR(T66, T18, T19);
    XOR(T67, T20, T21);
    XOR(T68, T22, T67);
    XOR(T69, T23, T24);
    XOR(T70, T25, T26);
    XOR(T71, T69, T70);
    XOR(T72, T27, T28);
    XOR(T73, T29, T32);
    XOR(T74, T30, T31);
    XOR(T75, T52, T55);
    XOR(T76, T48, T51);
    XOR(T77, T54, T76);
    XOR(T78, T44, T47);
    XOR(T79, T50, T53);
    XOR(T80, T78, T79);
    XOR(T81, T43, T46);
    XOR(T82, T49, T81);
    XOR(T83, T42, T45);
    XOR(T84, T71, T74);
    XOR(T85, T41, T16);
    XOR(T86, T85, T68);
    XOR(T87, T66, T65);
    XOR(T88, T83, T87);
    XOR(T89, T58, T59);
    XOR(T90, T72, T73);
    XOR(T91, T74, T17);
    XOR(T92, T64, T91);
    XOR(T93, T82, T92);
    XOR(T94, T80, T62);
    XOR(T95, T94, T90);
    ASSIGN(C7, T95);
    XOR(T96, T41, T77);
    XOR(T97, T84, T89);
    XOR(T98, T96, T97);
    ASSIGN(C6, T98);
    XOR(T99, T57, T74);
    XOR(T100, T83, T75);
    XOR(T101, T86, T90);
    XOR(T102, T99, T100);
    XOR(T103, T101, T102);
    ASSIGN(C5, T103);
    XOR(T104, T1, T56);
    XOR(T105, T90, T104);
    XOR(T106, T82, T84);
    XOR(T107, T88, T105);
    XOR(T108, T106, T107);
    ASSIGN(C4, T108);
    XOR(T109, T71, T62);
    XOR(T110, T86, T109);
    XOR(T111, T110, T93);
    ASSIGN(C3, T111);
    XOR(T112, T86, T88);
    XOR(T113, T89, T112);
    ASSIGN(C2, T113);
    XOR(T114, T57, T32);
    XOR(T115, T114, T88);
    XOR(T116, T115, T93);
    ASSIGN(C1, T116);
    XOR(T117, T93, T1);
    ASSIGN(C0, T117);

    res[0] = C0;
    res[1] = C1;
    res[2] = C2;
    res[3] = C3;
    res[4] = C4;
    res[5] = C5;
    res[6] = C6;
    res[7] = C7;

    #undef XOR
    #undef AND
    #undef ASSIGN

    return res;
}