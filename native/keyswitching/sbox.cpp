#include "sbox.hpp"

std::function<CryptoBitset<8>
                (const CryptoBitset<8>&)>
AES128_SBox_Forward = [](const CryptoBitset<8>& input) 
{
    CryptoBitset<8> output(input);
    // Top linear transform in forward direction
    // Note: little endian encoding needs some tweaks
    CryptoBit U0 = input[7];
    CryptoBit U1 = input[6];
    CryptoBit U2 = input[5];
    CryptoBit U3 = input[4];
    CryptoBit U4 = input[3];
    CryptoBit U5 = input[2];
    CryptoBit U6 = input[1];
    CryptoBit U7 = input[0];

#define XOR(R0, R1, R2) const CryptoBit R0 = R1 ^ R2
#define AND(R0, R1, R2) const CryptoBit R0 = R1 & R2

    XOR( T1,  U0,  U3);
    XOR( T2,  U0,  U5);
    XOR( T3,  U0,  U6);
    XOR( T4,  U3,  U5);
    XOR( T5,  U4,  U6);
    XOR( T6,  T1,  T5);
    XOR( T7,  U1,  U2);
    XOR( T8,  U7,  T6);
    XOR( T9,  U7,  T7);
    XOR(T10,  T6,  T7);
    XOR(T11,  U1,  U5);
    XOR(T12,  U2,  U5);
    XOR(T13,  T3,  T4);
    XOR(T14,  T6, T11);
    XOR(T15,  T5, T11);
    XOR(T16,  T5, T12);
    XOR(T17,  T9, T16);
    XOR(T18,  U3,  U7);
    XOR(T19,  T7, T18);
    XOR(T20,  T1, T19);
    XOR(T21,  U6,  U7);
    XOR(T22,  T7, T21);
    XOR(T23,  T2, T22);
    XOR(T24,  T2, T10);
    XOR(T25, T20, T17);
    XOR(T26,  T3, T16);
    XOR(T27,  T1, T12);

    // Shared part of AES S-box circuit
    CryptoBit D = U7;
    AND(M1,  T13,  T6);
    AND(M2,  T23,  T8);
    XOR(M3,  T14,  M1);
    AND(M4,  T19,   D);
    XOR(M5,   M4,  M1);
    AND(M6,   T3, T16);
    AND(M7,  T22,  T9);
    XOR(M8,  T26,  M6);
    AND(M9,  T20, T17);
    XOR(M10,  M9,  M6);
    AND(M11,  T1, T15);
    AND(M12,  T4, T27);
    XOR(M13, M12, M11);
    AND(M14,  T2, T10);
    XOR(M15, M14, M11);
    XOR(M16,  M3,  M2);
    XOR(M17,  M5, T24);
    XOR(M18,  M8,  M7);
    XOR(M19, M10, M15);
    XOR(M20, M16, M13);
    XOR(M21, M17, M15);
    XOR(M22, M18, M13);
    XOR(M23, M19, T25);
    XOR(M24, M22, M23);
    AND(M25, M22, M20);
    XOR(M26, M21, M25);
    XOR(M27, M20, M21);
    XOR(M28, M23, M25);
    AND(M29, M28, M27);
    AND(M30, M26, M24);
    AND(M31, M20, M23);
    AND(M32, M27, M31);
    XOR(M33, M27, M25);
    AND(M34, M21, M22);
    AND(M35, M24, M34);
    XOR(M36, M24, M25);
    XOR(M37, M21, M29);
    XOR(M38, M32, M33);
    XOR(M39, M23, M30);
    XOR(M40, M35, M36);
    XOR(M41, M38, M40);
    XOR(M42, M37, M39);
    XOR(M43, M37, M38);
    XOR(M44, M39, M40);
    XOR(M45, M42, M41);
    AND(M46, M44,  T6);
    AND(M47, M40,  T8);
    AND(M48, M39,   D);
    AND(M49, M43, T16);
    AND(M50, M38,  T9);
    AND(M51, M37, T17);
    AND(M52, M42, T15);
    AND(M53, M45, T27);
    AND(M54, M41, T10);
    AND(M55, M44, T13);
    AND(M56, M40, T23);
    AND(M57, M39, T19);
    AND(M58, M43,  T3);
    AND(M59, M38, T22);
    AND(M60, M37, T20);
    AND(M61, M42,  T1);
    AND(M62, M45,  T4);
    AND(M63, M41,  T2);

    // Bottom linear transform in forward direction
    XOR( L0, M61, M62);
    XOR( L1, M50, M56);
    XOR( L2, M46, M48);
    XOR( L3, M47, M55);
    XOR( L4, M54, M58);
    XOR( L5, M49, M61);
    XOR( L6, M62,  L5);
    XOR( L7, M46,  L3);
    XOR( L8, M51, M59);
    XOR( L9, M52, M53);
    XOR(L10, M53,  L4);
    XOR(L11, M60,  L2);
    XOR(L12, M48, M51);
    XOR(L13, M50,  L0);
    XOR(L14, M52, M61);
    XOR(L15, M55,  L1);
    XOR(L16, M56,  L0);
    XOR(L17, M57,  L1);
    XOR(L18, M58,  L8);
    XOR(L19, M63,  L4);
    XOR(L20,  L0,  L1);
    XOR(L21,  L1,  L7);
    XOR(L22,  L3, L12);
    XOR(L23, L18,  L2);
    XOR(L24, L15,  L9);
    XOR(L25,  L6, L10);
    XOR(L26,  L7,  L9);
    XOR(L27,  L8, L10);
    XOR(L28, L11, L14);
    XOR(L29, L11, L17);

#undef XOR
#undef AND

    output[7] = L6 ^ L24;
    output[6] = L16.xnor_op(L26);
    output[5] = L19.xnor_op(L28);
    output[4] = L6 ^ L21;
    output[3] = L20 ^ L22;
    output[2] = L25 ^ L29;
    output[1] = L13.xnor_op(L27);
    output[0] = L6.xnor_op(L23);
    return output;
};

std::function<CryptoBitset<8>
                (const CryptoBitset<8>&)>
AES128_SBox_Forward_Parallel = [](const CryptoBitset<8>& input) 
{
    CryptoBitset<8> output(input);
    // Top linear transform in forward direction
    // Note: little endian encoding needs some tweaks
    CryptoBit U0 = input[7];
    CryptoBit U1 = input[6];
    CryptoBit U2 = input[5];
    CryptoBit U3 = input[4];
    CryptoBit U4 = input[3];
    CryptoBit U5 = input[2];
    CryptoBit U6 = input[1];
    CryptoBit U7 = input[0];

/*
    XOR( T1,  U0,  U3);
    XOR( T2,  U0,  U5);
    XOR( T3,  U0,  U6);
    XOR( T4,  U3,  U5);
    XOR( T5,  U4,  U6);
    XOR( T6,  T1,  T5);
    XOR( T7,  U1,  U2);
    XOR( T8,  U7,  T6);
    XOR( T9,  U7,  T7);
    XOR(T10,  T6,  T7);
    XOR(T11,  U1,  U5);
    XOR(T12,  U2,  U5);
    XOR(T13,  T3,  T4);
    XOR(T14,  T6, T11);
    XOR(T15,  T5, T11);
    XOR(T16,  T5, T12);
    XOR(T17,  T9, T16);
    XOR(T18,  U3,  U7);
    XOR(T19,  T7, T18);
    XOR(T20,  T1, T19);
    XOR(T21,  U6,  U7);
    XOR(T22,  T7, T21);
    XOR(T23,  T2, T22);
    XOR(T24,  T2, T10);
    XOR(T25, T20, T17);
    XOR(T26,  T3, T16);
    XOR(T27,  T1, T12);
*/

    std::function<CryptoBit(CryptoBit const&, CryptoBit const&)> fXOR = 
    [](CryptoBit const& a, CryptoBit const& b) {
        return a ^ b;
    };
    std::function<CryptoBit(CryptoBit const&, CryptoBit const&)> fAND = 
    [](CryptoBit const& a, CryptoBit const& b) {
        return a & b;
    };

#define XOR(R0, R1, R2) fXOR, R0##ft, R1, R2
#define AND(R0, R1, R2) fAND, R0, R1, R2

#define PARENS ()

#define EXPAND(...)  EXPAND4(EXPAND4(EXPAND4(EXPAND4(__VA_ARGS__))))
#define EXPAND4(...) EXPAND3(EXPAND3(EXPAND3(EXPAND3(__VA_ARGS__))))
#define EXPAND3(...) EXPAND2(EXPAND2(EXPAND2(EXPAND2(__VA_ARGS__))))
#define EXPAND2(...) EXPAND1(EXPAND1(EXPAND1(EXPAND1(__VA_ARGS__))))
#define EXPAND1(...) __VA_ARGS__

 // => F(a) F(b) F(c) F(1) F(2) F(3)
#define for_each(macro, ...)                                    \
  __VA_OPT__(EXPAND(FOR_EACH_HELPER(macro, __VA_ARGS__)))
#define FOR_EACH_HELPER(macro, a1, ...)                         \
  macro(a1)                                                     \
  __VA_OPT__(FOR_EACH_AGAIN PARENS (macro, __VA_ARGS__))
#define FOR_EACH_AGAIN() FOR_EACH_HELPER

#define init_future(x)     std::future<CryptoBit> x##ft;
#define retreive_future(x) const CryptoBit x = x##ft.get();

    for_each(init_future, T1, T2, T3, T4, T5, T7, T11, T12, T18, T21);
    ExecInParallel(
        XOR( T1,  U0,  U3),
        XOR( T2,  U0,  U5),
        XOR( T3,  U0,  U6),
        XOR( T4,  U3,  U5),
        XOR( T5,  U4,  U6),
        XOR( T7,  U1,  U2),
        XOR(T11,  U1,  U5),
        XOR(T12,  U2,  U5),
        XOR(T18,  U3,  U7),
        XOR(T21,  U6,  U7)
    );
    for_each(retreive_future, T1, T2, T3, T4, T5, T7, T11, T12, T18, T21);

    for_each(init_future, T6, T9, T13, T15, T16, T19, T22, T27);
    ExecInParallel(
        XOR( T6,  T1,  T5),
        XOR( T9,  U7,  T7),
        XOR(T13,  T3,  T4),
        XOR(T15,  T5, T11),
        XOR(T16,  T5, T12),
        XOR(T19,  T7, T18),
        XOR(T22,  T7, T21),
        XOR(T27,  T1, T12)
    );
    for_each(retreive_future, T6, T9, T13, T15, T16, T19, T22, T27);

    for_each(init_future, T8, T10, T14, T17, T20, T23, T26);
    ExecInParallel(
        XOR( T8,  U7,  T6),
        XOR(T10,  T6,  T7),
        XOR(T14,  T6, T11),
        XOR(T17,  T9, T16),
        XOR(T20,  T1, T19),
        XOR(T23,  T2, T22),
        XOR(T26,  T3, T16)
    );
    for_each(retreive_future, T8, T10, T14, T17, T20, T23, T26);

    for_each(init_future, T24, T25);
    ExecInParallel(
        XOR(T24,  T2, T10),
        XOR(T25, T20, T17)
    );
    for_each(retreive_future, T24, T25);

#undef XOR
#undef AND

#define XOR(R0, R1, R2) std::future<CryptoBit> R0##_future = std::async(std::launch::async, fXOR, R1, R2);
#define WAIT(R0) R0##_future.wait();
#define GET(R0) const CryptoBit R0 = R0##_future.get();

/*
    XOR( T1,  U0,  U3);
    XOR( T2,  U0,  U5);
    XOR( T3,  U0,  U6);
    XOR( T4,  U3,  U5);
    XOR( T5,  U4,  U6);
    XOR( T7,  U1,  U2);
    XOR(T11,  U1,  U5);
    XOR(T12,  U2,  U5);
    XOR(T18,  U3,  U7);
    XOR(T21,  U6,  U7);

    FOR_EACH(WAIT, T1, T2, T3, T4, T5, T7, T11, T12, T18, T21)
    FOR_EACH(GET , T1, T2, T3, T4, T5, T7, T11, T12, T18, T21)

    XOR( T6,  T1,  T5);
    XOR( T9,  U7,  T7);
    XOR(T13,  T3,  T4);
    XOR(T15,  T5, T11);
    XOR(T16,  T5, T12);
    XOR(T19,  T7, T18);
    XOR(T22,  T7, T21);
    XOR(T27,  T1, T12);

    FOR_EACH(WAIT, T6, T9, T13, T15, T16, T19, T22, T27)
    FOR_EACH(GET , T6, T9, T13, T15, T16, T19, T22, T27)

    XOR( T8,  U7,  T6);
    XOR(T10,  T6,  T7);
    XOR(T14,  T6, T11);
    XOR(T17,  T9, T16);
    XOR(T20,  T1, T19);
    XOR(T23,  T2, T22);
    XOR(T26,  T3, T16);

    FOR_EACH(WAIT, T8, T10, T14, T17, T20, T23, T26)
    FOR_EACH(GET , T8, T10, T14, T17, T20, T23, T26)

    XOR(T24,  T2, T10);
    XOR(T25, T20, T17);

    FOR_EACH(WAIT, T24, T25)
    FOR_EACH(GET, T24, T25)
*/
#undef XOR
#undef WAIT

#define XOR(R0, R1, R2) const CryptoBit R0 = R1 ^ R2
#define AND(R0, R1, R2) const CryptoBit R0 = R1 & R2

    // Shared part of AES S-box circuit
    CryptoBit D = U7;
    AND(M1,  T13,  T6);
    AND(M2,  T23,  T8);
    XOR(M3,  T14,  M1);
    AND(M4,  T19,   D);
    XOR(M5,   M4,  M1);
    AND(M6,   T3, T16);
    AND(M7,  T22,  T9);
    XOR(M8,  T26,  M6);
    AND(M9,  T20, T17);
    XOR(M10,  M9,  M6);
    AND(M11,  T1, T15);
    AND(M12,  T4, T27);
    XOR(M13, M12, M11);
    AND(M14,  T2, T10);
    XOR(M15, M14, M11);
    XOR(M16,  M3,  M2);
    XOR(M17,  M5, T24);
    XOR(M18,  M8,  M7);
    XOR(M19, M10, M15);
    XOR(M20, M16, M13);
    XOR(M21, M17, M15);
    XOR(M22, M18, M13);
    XOR(M23, M19, T25);
    XOR(M24, M22, M23);
    AND(M25, M22, M20);
    XOR(M26, M21, M25);
    XOR(M27, M20, M21);
    XOR(M28, M23, M25);
    AND(M29, M28, M27);
    AND(M30, M26, M24);
    AND(M31, M20, M23);
    AND(M32, M27, M31);
    XOR(M33, M27, M25);
    AND(M34, M21, M22);
    AND(M35, M24, M34);
    XOR(M36, M24, M25);
    XOR(M37, M21, M29);
    XOR(M38, M32, M33);
    XOR(M39, M23, M30);
    XOR(M40, M35, M36);
    XOR(M41, M38, M40);
    XOR(M42, M37, M39);
    XOR(M43, M37, M38);
    XOR(M44, M39, M40);
    XOR(M45, M42, M41);
    AND(M46, M44,  T6);
    AND(M47, M40,  T8);
    AND(M48, M39,   D);
    AND(M49, M43, T16);
    AND(M50, M38,  T9);
    AND(M51, M37, T17);
    AND(M52, M42, T15);
    AND(M53, M45, T27);
    AND(M54, M41, T10);
    AND(M55, M44, T13);
    AND(M56, M40, T23);
    AND(M57, M39, T19);
    AND(M58, M43,  T3);
    AND(M59, M38, T22);
    AND(M60, M37, T20);
    AND(M61, M42,  T1);
    AND(M62, M45,  T4);
    AND(M63, M41,  T2);

    // Bottom linear transform in forward direction
    XOR( L0, M61, M62);
    XOR( L1, M50, M56);
    XOR( L2, M46, M48);
    XOR( L3, M47, M55);
    XOR( L4, M54, M58);
    XOR( L5, M49, M61);
    XOR( L6, M62,  L5);
    XOR( L7, M46,  L3);
    XOR( L8, M51, M59);
    XOR( L9, M52, M53);
    XOR(L10, M53,  L4);
    XOR(L11, M60,  L2);
    XOR(L12, M48, M51);
    XOR(L13, M50,  L0);
    XOR(L14, M52, M61);
    XOR(L15, M55,  L1);
    XOR(L16, M56,  L0);
    XOR(L17, M57,  L1);
    XOR(L18, M58,  L8);
    XOR(L19, M63,  L4);
    XOR(L20,  L0,  L1);
    XOR(L21,  L1,  L7);
    XOR(L22,  L3, L12);
    XOR(L23, L18,  L2);
    XOR(L24, L15,  L9);
    XOR(L25,  L6, L10);
    XOR(L26,  L7,  L9);
    XOR(L27,  L8, L10);
    XOR(L28, L11, L14);
    XOR(L29, L11, L17);

    output[7] = L6 ^ L24;
    output[6] = L16.xnor_op(L26);
    output[5] = L19.xnor_op(L28);
    output[4] = L6 ^ L21;
    output[3] = L20 ^ L22;
    output[2] = L25 ^ L29;
    output[1] = L13.xnor_op(L27);
    output[0] = L6.xnor_op(L23);
    return output;
};

std::function<CryptoBitset<8>
              (const CryptoBitset<8>&)>
AES128_SBox_Reverse = [](const CryptoBitset<8>& input) 
{
    CryptoBitset<8> output(input);

    // Top linear transform in reverse direction
    CryptoBit U0 = input[7];
    CryptoBit U1 = input[6];
    CryptoBit U2 = input[5];
    CryptoBit U3 = input[4];
    CryptoBit U4 = input[3];
    CryptoBit U5 = input[2];
    CryptoBit U6 = input[1];
    CryptoBit U7 = input[0];

    CryptoBit T23 = U0 ^ U3;
    CryptoBit T22 = U1.xnor_op(U3);
    CryptoBit T2 = U0.xnor_op(U1);
    CryptoBit T1 = U3 ^ U4;
    CryptoBit T24 = U4.xnor_op(U7);
    CryptoBit R5 = U6 ^ U7;
    CryptoBit T8 = U1.xnor_op(T23);
    CryptoBit T19 = T22 ^ R5;
    CryptoBit T9 = U7.xnor_op(T1);
    CryptoBit T10 = T2 ^ T24;
    CryptoBit T13 = T2 ^ R5;
    CryptoBit T3 = T1 ^ R5;
    CryptoBit T25 = U2.xnor_op(T1);
    CryptoBit R13 = U1 ^ U6;
    CryptoBit T17 = U2.xnor_op(T19);
    CryptoBit T20 = T24 ^ R13;
    CryptoBit T4 = U4 ^ T8;
    CryptoBit R17 = U2.xnor_op(U5);
    CryptoBit R18 = U5.xnor_op(U6);
    CryptoBit R19 = U2.xnor_op(U4);
    CryptoBit Y5 = U0 ^ R17;
    CryptoBit T6 = T22 ^ R17;
    CryptoBit T16 = R13 ^ R19;
    CryptoBit T27 = T1 ^ R18;
    CryptoBit T15 = T10 ^ T27;
    CryptoBit T14 = T10 ^ R18;
    CryptoBit T26 = T3 ^ T16;

    // Shared part of AES S-box circuit
    CryptoBit D = Y5;
    CryptoBit M1 = T13 & T6;
    CryptoBit M2 = T23 & T8;
    CryptoBit M3 = T14 ^ M1;
    CryptoBit M4 = T19 & D;
    CryptoBit M5 = M4 ^ M1;
    CryptoBit M6 = T3 & T16;
    CryptoBit M7 = T22 & T9;
    CryptoBit M8 = T26 ^ M6;
    CryptoBit M9 = T20 & T17;
    CryptoBit M10 = M9 ^ M6;
    CryptoBit M11 = T1 & T15;
    CryptoBit M12 = T4 & T27;
    CryptoBit M13 = M12 ^ M11;
    CryptoBit M14 = T2 & T10;
    CryptoBit M15 = M14 ^ M11;
    CryptoBit M16 = M3 ^ M2;
    CryptoBit M17 = M5 ^ T24;
    CryptoBit M18 = M8 ^ M7;
    CryptoBit M19 = M10 ^ M15;
    CryptoBit M20 = M16 ^ M13;
    CryptoBit M21 = M17 ^ M15;
    CryptoBit M22 = M18 ^ M13;
    CryptoBit M23 = M19 ^ T25;
    CryptoBit M24 = M22 ^ M23;
    CryptoBit M25 = M22 & M20;
    CryptoBit M26 = M21 ^ M25;
    CryptoBit M27 = M20 ^ M21;
    CryptoBit M28 = M23 ^ M25;
    CryptoBit M29 = M28 & M27;
    CryptoBit M30 = M26 & M24;
    CryptoBit M31 = M20 & M23;
    CryptoBit M32 = M27 & M31;
    CryptoBit M33 = M27 ^ M25;
    CryptoBit M34 = M21 & M22;
    CryptoBit M35 = M24 & M34;
    CryptoBit M36 = M24 ^ M25;
    CryptoBit M37 = M21 ^ M29;
    CryptoBit M38 = M32 ^ M33;
    CryptoBit M39 = M23 ^ M30;
    CryptoBit M40 = M35 ^ M36;
    CryptoBit M41 = M38 ^ M40;
    CryptoBit M42 = M37 ^ M39;
    CryptoBit M43 = M37 ^ M38;
    CryptoBit M44 = M39 ^ M40;
    CryptoBit M45 = M42 ^ M41;
    CryptoBit M46 = M44 & T6;
    CryptoBit M47 = M40 & T8;
    CryptoBit M48 = M39 & D;
    CryptoBit M49 = M43 & T16;
    CryptoBit M50 = M38 & T9;
    CryptoBit M51 = M37 & T17;
    CryptoBit M52 = M42 & T15;
    CryptoBit M53 = M45 & T27;
    CryptoBit M54 = M41 & T10;
    CryptoBit M55 = M44 & T13;
    CryptoBit M56 = M40 & T23;
    CryptoBit M57 = M39 & T19;
    CryptoBit M58 = M43 & T3;
    CryptoBit M59 = M38 & T22;
    CryptoBit M60 = M37 & T20;
    CryptoBit M61 = M42 & T1;
    CryptoBit M62 = M45 & T4;
    CryptoBit M63 = M41 & T2;

    // Bottom linear transform in reverse direction
    CryptoBit P0 = M52 ^ M61;
    CryptoBit P1 = M58 ^ M59;
    CryptoBit P2 = M54 ^ M62;
    CryptoBit P3 = M47 ^ M50;
    CryptoBit P4 = M48 ^ M56;
    CryptoBit P5 = M46 ^ M51;
    CryptoBit P6 = M49 ^ M60;
    CryptoBit P7 = P0 ^ P1;
    CryptoBit P8 = M50 ^ M53;
    CryptoBit P9 = M55 ^ M63;
    CryptoBit P10 = M57 ^ P4;
    CryptoBit P11 = P0 ^ P3;
    CryptoBit P12 = M46 ^ M48;
    CryptoBit P13 = M49 ^ M51;
    CryptoBit P14 = M49 ^ M62;
    CryptoBit P15 = M54 ^ M59;
    CryptoBit P16 = M57 ^ M61;
    CryptoBit P17 = M58 ^ P2;
    CryptoBit P18 = M63 ^ P5;
    CryptoBit P19 = P2 ^ P3;
    CryptoBit P20 = P4 ^ P6;
    CryptoBit P22 = P2 ^ P7;
    CryptoBit P23 = P7 ^ P8;
    CryptoBit P24 = P5 ^ P7;
    CryptoBit P25 = P6 ^ P10;
    CryptoBit P26 = P9 ^ P11;
    CryptoBit P27 = P10 ^ P18;
    CryptoBit P28 = P11 ^ P25;
    CryptoBit P29 = P15 ^ P20;

    output[7] = P13 ^ P22;
    output[6] = P26 ^ P29;
    output[5] = P17 ^ P28;
    output[4] = P12 ^ P22;
    output[3] = P23 ^ P27;
    output[2] = P19 ^ P24;
    output[1] = P14 ^ P23;
    output[0] = P9  ^ P16;

    return output;
};

#undef XOR

S_Box<uint8_t, 8> Sbox_AES128(AES128_SBox_Forward, AES128_SBox_Reverse);