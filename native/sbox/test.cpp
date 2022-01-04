#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "sbox.hpp"

using namespace seal;
using namespace std;

TEST_CASE("Test AND", "[Test1]")
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = a & ctxt.c0();
    CryptoBit d = a & ctxt.c1();
    CryptoBit e = b & ctxt.c0();
    CryptoBit f = b & ctxt.c1();

    REQUIRE ( c.decrypt() == 0b0 );
    REQUIRE ( d.decrypt() == 0b0 );
    REQUIRE ( e.decrypt() == 0b0 );
    REQUIRE ( f.decrypt() == 0b1 );
}

TEST_CASE("Test OR", "[Test2]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = a | ctxt.c0();
    CryptoBit d = a | ctxt.c1();
    CryptoBit e = b | ctxt.c0();
    CryptoBit f = b | ctxt.c1();

    REQUIRE ( c.decrypt() == 0b0 );
    REQUIRE ( d.decrypt() == 0b1 );
    REQUIRE ( e.decrypt() == 0b1 );
    REQUIRE ( f.decrypt() == 0b1 );
}

TEST_CASE("Test XOR", "[Test3]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = a ^ ctxt.c0();
    CryptoBit d = a ^ ctxt.c1();
    CryptoBit e = b ^ ctxt.c0();
    CryptoBit f = b ^ ctxt.c1();

    REQUIRE ( c.decrypt() == 0b0 );
    REQUIRE ( d.decrypt() == 0b1 );
    REQUIRE ( e.decrypt() == 0b1 );
    REQUIRE ( f.decrypt() == 0b0 );
}

TEST_CASE("Test NOT", "[Test4]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = !a;
    CryptoBit d = !b;

    REQUIRE ( c.decrypt() == 0b1 );
    REQUIRE ( d.decrypt() == 0b0 );
}

TEST_CASE("Test XNOR", "[Test5]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = a == ctxt.c0();
    CryptoBit d = a == ctxt.c1();
    CryptoBit e = b == ctxt.c0();
    CryptoBit f = b == ctxt.c1();

    REQUIRE ( c.decrypt() == 0b1 );
    REQUIRE ( d.decrypt() == 0b0 );
    REQUIRE ( e.decrypt() == 0b0 );
    REQUIRE ( f.decrypt() == 0b1 );
}

TEST_CASE("Test set to 0", "[Test6]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    REQUIRE ( a.set_to_0().decrypt() == 0b0 );
    REQUIRE ( b.set_to_0().decrypt() == 0b0 );
}

TEST_CASE("Test set to 1", "[Test7]") 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    REQUIRE ( a.set_to_1().decrypt() == 0b1 );
    REQUIRE ( b.set_to_1().decrypt() == 0b1 );
}

TEST_CASE("Encryption and Decryption via the bitfield", "[Test8]")
{
    BitEncryptionContext ctxt;

    uint16_t inputData = 7;
    CryptoBitset<uint16_t, 5> field(ctxt, inputData);
    REQUIRE ( field.decrypt() == 7 );
    
    // 00111 -> 00110
    field[0].set_to_0();
    REQUIRE ( field.decrypt() == 6 );

    std::cout << "[Test8] (min) noise budget: " << field.min_noise_budget() << " bits"
              << std::endl;

    // 00011
    inputData = 3;
    CryptoBitset<uint16_t, 5> field2(ctxt, inputData);
    CryptoBitset<uint16_t, 5> field3 = !(field & field2);
    // 00110 & 00011 -> 00010 -> 11101
    REQUIRE ( field3.decrypt() == 29 );
}

TEST_CASE("S-Box by value check", "[Test9]")
{
    BitEncryptionContext ctxt;

    S_Box<uint32_t, 1> sbox1(
        LUTInput(0b0) ->* LUTOutput(0b1),
        LUTInput(0b1) ->* LUTOutput(0b0)
    );

    CryptoBitset<uint32_t, 1> input_0(ctxt, 0b0);
    CryptoBitset<uint32_t, 1> input_1(ctxt, 0b1);

    CryptoBitset<uint32_t, 1> output_0 = sbox1.apply(ctxt, input_0);
    CryptoBitset<uint32_t, 1> output_1 = sbox1.apply(ctxt, input_1);

    std::cout << "[Test9] (min) output_0 noise budget: " << output_0.min_noise_budget() 
              << " bits" << std::endl;
    std::cout << "[Test9] (min) output_1 noise budget: " << output_1.min_noise_budget() 
              << " bits" << std::endl;

    REQUIRE ( output_0.decrypt() == 0b1 );
    REQUIRE ( output_1.decrypt() == 0b0 );

    S_Box<uint32_t, 2> sbox2(
        LUTInput(0b00) ->* LUTOutput(0b11),
        LUTInput(0b01) ->* LUTOutput(0b10),
        LUTInput(0b10) ->* LUTOutput(0b01),
        LUTInput(0b11) ->* LUTOutput(0b00)
    );

    CryptoBitset<uint32_t, 2> input_00(ctxt, 0b00);
    CryptoBitset<uint32_t, 2> input_01(ctxt, 0b01);
    CryptoBitset<uint32_t, 2> input_10(ctxt, 0b10);
    CryptoBitset<uint32_t, 2> input_11(ctxt, 0b11);

    CryptoBitset<uint32_t, 2> output_00 = sbox2.apply(ctxt, input_00);
    CryptoBitset<uint32_t, 2> output_01 = sbox2.apply(ctxt, input_01);
    CryptoBitset<uint32_t, 2> output_10 = sbox2.apply(ctxt, input_10);
    CryptoBitset<uint32_t, 2> output_11 = sbox2.apply(ctxt, input_11);

    std::cout << "[Test9] (min) output_00 noise budget: " 
              << output_00.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) output_01 noise budget: " 
              << output_01.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) output_10 noise budget: " 
              << output_10.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) output_11 noise budget: " 
              << output_11.min_noise_budget() << " bits" << std::endl;

    REQUIRE ( output_00.decrypt() == 0b11 );
    REQUIRE ( output_01.decrypt() == 0b10 );
    REQUIRE ( output_10.decrypt() == 0b01 );
    REQUIRE ( output_11.decrypt() == 0b00 );

    // if the relinearization is not activated, the following lines are mandatory:
    // output_00.refresh();
    // output_01.refresh();
    // output_10.refresh();
    // output_11.refresh();

    // 0b11 -> 0b00
    CryptoBitset<uint32_t, 2> reversed_output_00 = sbox2.reverse(ctxt, output_00);
    // 0b10 -> 0b01
    CryptoBitset<uint32_t, 2> reversed_output_01 = sbox2.reverse(ctxt, output_01);
    // 0b01 -> 0b10
    CryptoBitset<uint32_t, 2> reversed_output_10 = sbox2.reverse(ctxt, output_10);
    // 0b00 -> 0b11
    CryptoBitset<uint32_t, 2> reversed_output_11 = sbox2.reverse(ctxt, output_11);

    std::cout << "[Test9] (min) reversed_output_00 noise budget: " 
              << output_00.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) reversed_output_01 noise budget: " 
              << output_01.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) reversed_output_10 noise budget: " 
              << output_10.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test9] (min) reversed_output_11 noise budget: " 
              << output_11.min_noise_budget() << " bits" << std::endl;

    REQUIRE ( reversed_output_00.decrypt() == 0b00 );
    REQUIRE ( reversed_output_01.decrypt() == 0b01 );
    REQUIRE ( reversed_output_10.decrypt() == 0b10 );
    REQUIRE ( reversed_output_11.decrypt() == 0b11 );
}

TEST_CASE("S-Box by functions check", "[Test10]")
{
    BitEncryptionContext ctxt;

    std::function<CryptoBitset<uint32_t, 2>
                 (const CryptoBitset<uint32_t, 2>&)>
    inverter = [](const CryptoBitset<uint32_t, 2>& arg) 
    {
        return !arg;
    };

    // The inverter is its own inverse
    std::function<CryptoBitset<uint32_t, 2>
                 (const CryptoBitset<uint32_t, 2>&)>
    inverter_reverse = inverter;

    S_Box<uint32_t, 2> sbox(inverter, inverter_reverse);

    CryptoBitset<uint32_t, 2> input_00(ctxt, 0b00);
    CryptoBitset<uint32_t, 2> input_01(ctxt, 0b01);
    CryptoBitset<uint32_t, 2> input_10(ctxt, 0b10);
    CryptoBitset<uint32_t, 2> input_11(ctxt, 0b11);

    CryptoBitset<uint32_t, 2> output_00 = sbox.apply(ctxt, input_00);
    CryptoBitset<uint32_t, 2> output_01 = sbox.apply(ctxt, input_01);
    CryptoBitset<uint32_t, 2> output_10 = sbox.apply(ctxt, input_10);
    CryptoBitset<uint32_t, 2> output_11 = sbox.apply(ctxt, input_11);

    std::cout << "[Test10] (min) output_00 noise budget: " 
              << output_00.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test10] (min) output_01 noise budget: " 
              << output_01.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test10] (min) output_10 noise budget: " 
              << output_10.min_noise_budget() << " bits" << std::endl;
    std::cout << "[Test10] (min) output_11 noise budget: " 
              << output_11.min_noise_budget() << " bits" << std::endl;

    REQUIRE ( output_00.decrypt() == 0b11 );
    REQUIRE ( output_01.decrypt() == 0b10 );
    REQUIRE ( output_10.decrypt() == 0b01 );
    REQUIRE ( output_11.decrypt() == 0b00 );
}

TEST_CASE("Shift and rotation behaviour", "[Test11]")
{
    BitEncryptionContext ctxt;
    // 0b0001110
    CryptoBitset<uint32_t, 7> bits(ctxt, 14);
    REQUIRE ( (bits << 2).decrypt() == 0b0111000 );
    REQUIRE ( (bits >> 3).decrypt() == 0b0000001 );
    REQUIRE ( (bits >> 8).decrypt() == 0b0000000 );

    // 0b1110
    CryptoBitset<uint32_t, 4> bits2(ctxt, 14);

    REQUIRE ( bits2.rotate_left(2).decrypt() == 0b1011 );
    REQUIRE ( bits2.rotate_left(5).decrypt() == 0b1101 );

    REQUIRE ( bits2.rotate_right(2).decrypt() == 0b1011 );
    REQUIRE ( bits2.rotate_right(5).decrypt() == 0b0111 );
}

TEST_CASE("AES S-Box (Bit-slice version)", "[Test12]")
{
    BitEncryptionContext ctxt;

    std::function<CryptoBitset<uint32_t, 8>
                 (const CryptoBitset<uint32_t, 8>&)>
    AES128_SBox_Forward = [](const CryptoBitset<uint32_t, 8>& input) 
    {
        CryptoBitset<uint32_t, 8> output(input);
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

#define XOR(R0, R1, R2) CryptoBit R0 = R1 ^ R2

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

        // Bottom linear transform in forward direction
        CryptoBit L0 = M61 ^ M62;
        CryptoBit L1 = M50 ^ M56;
        CryptoBit L2 = M46 ^ M48;
        CryptoBit L3 = M47 ^ M55;
        CryptoBit L4 = M54 ^ M58;
        CryptoBit L5 = M49 ^ M61;
        CryptoBit L6 = M62 ^ L5;
        CryptoBit L7 = M46 ^ L3;
        CryptoBit L8 = M51 ^ M59;
        CryptoBit L9 = M52 ^ M53;
        CryptoBit L10 = M53 ^ L4;
        CryptoBit L11 = M60 ^ L2;
        CryptoBit L12 = M48 ^ M51;
        CryptoBit L13 = M50 ^ L0;
        CryptoBit L14 = M52 ^ M61;
        CryptoBit L15 = M55 ^ L1;
        CryptoBit L16 = M56 ^ L0;
        CryptoBit L17 = M57 ^ L1;
        CryptoBit L18 = M58 ^ L8;
        CryptoBit L19 = M63 ^ L4;
        CryptoBit L20 = L0 ^ L1;
        CryptoBit L21 = L1 ^ L7;
        CryptoBit L22 = L3 ^ L12;
        CryptoBit L23 = L18 ^ L2;
        CryptoBit L24 = L15 ^ L9;
        CryptoBit L25 = L6 ^ L10;
        CryptoBit L26 = L7 ^ L9;
        CryptoBit L27 = L8 ^ L10;
        CryptoBit L28 = L11 ^ L14;
        CryptoBit L29 = L11 ^ L17;

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

    // The inverter is its own inverse
    std::function<CryptoBitset<uint32_t, 8>
                 (const CryptoBitset<uint32_t, 8>&)>
    AES128_SBox_Reverse = [](const CryptoBitset<uint32_t, 8>& input) 
    {
        CryptoBitset<uint32_t, 8> output(input);

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

    S_Box<uint32_t, 8> sbox(AES128_SBox_Forward, AES128_SBox_Reverse);

    CryptoBitset<uint32_t, 8> input_00(ctxt, 0x00);
    CryptoBitset<uint32_t, 8> output_00 = sbox.apply(ctxt, input_00);

    std::cout << "[Test12] decrypt value: " << output_00.decrypt() << std::endl;
    std::cout << "[Test12] (min) noise budget: " << output_00.min_noise_budget() << std::endl;

    REQUIRE ( output_00.decrypt() == 0x63 );
    output_00.refresh();
    REQUIRE ( sbox.reverse(ctxt, output_00).decrypt() == 0x00 );

    CryptoBitset<uint32_t, 8> input_03(ctxt, 0x03);
    CryptoBitset<uint32_t, 8> output_03 = sbox.apply(ctxt, input_03);

    REQUIRE ( output_03.decrypt() == 0x7b );
    output_03.refresh();
    REQUIRE ( sbox.reverse(ctxt, output_03).decrypt() == 0x03 );

    CryptoBitset<uint32_t, 8> input_ee(ctxt, 0xee);
    CryptoBitset<uint32_t, 8> output_ee = sbox.apply(ctxt, input_ee);
    REQUIRE ( output_ee.decrypt() == 0x28 );
    output_ee.refresh();
    REQUIRE ( sbox.reverse(ctxt, output_ee).decrypt() == 0xee );

    CryptoBitset<uint32_t, 8> input_a8(ctxt, 0xa8);
    CryptoBitset<uint32_t, 8> output_a8 = sbox.apply(ctxt, input_a8);
    REQUIRE ( output_a8.decrypt() == 0xc2 );

    output_a8.refresh();
    REQUIRE ( sbox.reverse(ctxt, output_a8).decrypt() == 0xa8 );
}