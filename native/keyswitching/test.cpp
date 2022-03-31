#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "aes_he.hpp"
#include "sbox.hpp"
#include "GF256.hpp"

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
    CryptoBitset<5> field(ctxt, inputData);
    REQUIRE ( field.decrypt() == 7 );
    
    // 00111 -> 00110
    field[0].set_to_0();
    REQUIRE ( field.decrypt() == 6 );

    std::cout << "[Test8] (min) noise budget: " << field.min_noise_budget() << " bits"
              << std::endl;

    // 00011
    inputData = 3;
    CryptoBitset<5> field2(ctxt, inputData);
    CryptoBitset<5> field3 = !(field & field2);
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

    CryptoBitset<1> input_0(ctxt, 0b0);
    CryptoBitset<1> input_1(ctxt, 0b1);

    CryptoBitset<1> output_0 = sbox1.apply(ctxt, input_0);
    CryptoBitset<1> output_1 = sbox1.apply(ctxt, input_1);

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

    CryptoBitset<2> input_00(ctxt, 0b00);
    CryptoBitset<2> input_01(ctxt, 0b01);
    CryptoBitset<2> input_10(ctxt, 0b10);
    CryptoBitset<2> input_11(ctxt, 0b11);

    CryptoBitset<2> output_00 = sbox2.apply(ctxt, input_00);
    CryptoBitset<2> output_01 = sbox2.apply(ctxt, input_01);
    CryptoBitset<2> output_10 = sbox2.apply(ctxt, input_10);
    CryptoBitset<2> output_11 = sbox2.apply(ctxt, input_11);

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
    CryptoBitset<2> reversed_output_00 = sbox2.reverse(ctxt, output_00);
    // 0b10 -> 0b01
    CryptoBitset<2> reversed_output_01 = sbox2.reverse(ctxt, output_01);
    // 0b01 -> 0b10
    CryptoBitset<2> reversed_output_10 = sbox2.reverse(ctxt, output_10);
    // 0b00 -> 0b11
    CryptoBitset<2> reversed_output_11 = sbox2.reverse(ctxt, output_11);

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

    std::function<CryptoBitset<2>
                 (const CryptoBitset<2>&)>
    inverter = [](const CryptoBitset<2>& arg) 
    {
        return !arg;
    };

    // The inverter is its own inverse
    std::function<CryptoBitset<2>
                 (const CryptoBitset<2>&)>
    inverter_reverse = inverter;

    S_Box<uint32_t, 2> sbox(inverter, inverter_reverse);

    CryptoBitset<2> input_00(ctxt, 0b00);
    CryptoBitset<2> input_01(ctxt, 0b01);
    CryptoBitset<2> input_10(ctxt, 0b10);
    CryptoBitset<2> input_11(ctxt, 0b11);

    CryptoBitset<2> output_00 = sbox.apply(ctxt, input_00);
    CryptoBitset<2> output_01 = sbox.apply(ctxt, input_01);
    CryptoBitset<2> output_10 = sbox.apply(ctxt, input_10);
    CryptoBitset<2> output_11 = sbox.apply(ctxt, input_11);

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
    CryptoBitset<7> bits(ctxt, 14);
    REQUIRE ( (bits << 2).decrypt() == 0b0111000 );
    REQUIRE ( (bits >> 3).decrypt() == 0b0000001 );
    REQUIRE ( (bits >> 8).decrypt() == 0b0000000 );

    // 0b1110
    CryptoBitset<4> bits2(ctxt, 14);

    REQUIRE ( bits2.rotate_left(3).decrypt() == 0b0111 );
    REQUIRE ( bits2.rotate_left(5).decrypt() == 0b1101 );

    REQUIRE ( bits2.rotate_right(2).decrypt() == 0b1011 );
    REQUIRE ( bits2.rotate_right(5).decrypt() == 0b0111 );
}

TEST_CASE("AES S-Box (Bit-slice version) by procedure", "[Test12]")
{
    BitEncryptionContext ctxt;

    CryptoBitset<8> input_00(ctxt, 0x00);
    CryptoBitset<8> input_03(ctxt, 0x03);
    CryptoBitset<8> input_ee(ctxt, 0xee);
    CryptoBitset<8> input_a8(ctxt, 0xa8);

    CryptoBitset<8> output_00 = Sbox_AES128.apply(ctxt, input_00);
    CryptoBitset<8> output_03 = Sbox_AES128.apply(ctxt, input_03);
    CryptoBitset<8> output_ee = Sbox_AES128.apply(ctxt, input_ee);
    CryptoBitset<8> output_a8 = Sbox_AES128.apply(ctxt, input_a8);

    REQUIRE ( output_00.decrypt() == 0x63 );
    REQUIRE ( output_03.decrypt() == 0x7b );
    REQUIRE ( output_ee.decrypt() == 0x28 );
    REQUIRE ( output_a8.decrypt() == 0xc2 );

    std::cout << "[Test12] decrypt value: " << output_00.decrypt() << std::endl;
    std::cout << "[Test12] (min) noise budget: " << output_00.min_noise_budget() << std::endl;

    output_00.refresh();
    output_03.refresh();
    output_ee.refresh();
    output_a8.refresh();

    REQUIRE ( Sbox_AES128.reverse(ctxt, output_00).decrypt() == 0x00 );
    REQUIRE ( Sbox_AES128.reverse(ctxt, output_03).decrypt() == 0x03 );
    REQUIRE ( Sbox_AES128.reverse(ctxt, output_ee).decrypt() == 0xee );
    REQUIRE ( Sbox_AES128.reverse(ctxt, output_a8).decrypt() == 0xa8 );
}

/*
TEST_CASE("AES S-Box (Bit-slice version) by value", "[Test13]")
{
    BitEncryptionContext ctxt;

    S_Box<uint8_t, 8> sbox(
        LUTInput(0x00) ->* LUTOutput(0x63),
        LUTInput(0x01) ->* LUTOutput(0x7c),
        LUTInput(0x02) ->* LUTOutput(0x77),
        LUTInput(0x03) ->* LUTOutput(0x7b),
        LUTInput(0x04) ->* LUTOutput(0xf2),
        LUTInput(0x05) ->* LUTOutput(0x6b),
        LUTInput(0x06) ->* LUTOutput(0x6f),
        LUTInput(0x07) ->* LUTOutput(0xc5),
        ...
    );
}*/

TEST_CASE("Check conversion functions", "[Test14]")
{
    // Recall that we are here in little endian:
    std::array<uint8_t, 16> key = 
    // LSB...
    { 0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
    //                                        ...MSB
      0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76 };

    // convert the key array into a bitset
    std::bitset<128> bitsetkey = arrayToBitset(key);
    // create a bitset mask to preserve the last 64 bits 
    std::bitset<128> mask64(0xffffffffffffffff);

    // We test if we obtain the same 8 low bytes in the bitset
    uint64_t* low64bits = reinterpret_cast<uint64_t*>(key.data());
    REQUIRE (( 
        (bitsetkey & mask64).to_ullong() == *low64bits && 
        *low64bits == 0x67536450614B2D47
    ));

    // Same for the 8 up bytes of the bitset
    uint64_t* up64bits = reinterpret_cast<uint64_t*>(key.data())+1;
    REQUIRE ((
        (bitsetkey >> 64).to_ullong() == *up64bits && 
        *up64bits == 0x7635733270586B56
    ));
    
    // Finally, we check the conversion in the other side
    std::array<uint8_t, 16> newArray = bitsetToArray<uint8_t>(bitsetkey);
    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( newArray[i] == key[i] );
}

TEST_CASE("Split and Join methods", "[Test15]")
{
    BitEncryptionContext ctxt;

    CryptoBitset<8> encrypted_data(ctxt, 0b10110010);
    auto splitted_data = encrypted_data.split<4>();
    
    REQUIRE ( splitted_data.size() == 4 );
    REQUIRE ( splitted_data[0].decrypt() == 0b10 );
    REQUIRE ( splitted_data[1].decrypt() == 0b00 );
    REQUIRE ( splitted_data[2].decrypt() == 0b11 );
    REQUIRE ( splitted_data[3].decrypt() == 0b10 );

    splitted_data = encrypted_data.rotate_left(2).split<4>();

    REQUIRE ( encrypted_data.rotate_left(2).decrypt() == 0b11001010 );
    REQUIRE ( splitted_data.size() == 4 );
    REQUIRE ( splitted_data[0].decrypt() == 0b10 );
    REQUIRE ( splitted_data[1].decrypt() == 0b10 );
    REQUIRE ( splitted_data[2].decrypt() == 0b00 );
    REQUIRE ( splitted_data[3].decrypt() == 0b11 );

    std::array<uint8_t, 16> key = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76
    };

    CryptoBitset<128> encrypted_key(ctxt, arrayToBitset(key));
    // auto --> std::vector<CryptoBitset<32>>
    auto splitted_key = encrypted_key.split<4>();
    
    // 128/4 leads to 4 chunks of size 32
    REQUIRE ( splitted_key.size() == 4 );
    REQUIRE ( splitted_key[0].decrypt() == 0x614B2D47 );
    REQUIRE ( splitted_key[1].decrypt() == 0x67536450 );
    REQUIRE ( splitted_key[2].decrypt() == 0x70586B56 );
    REQUIRE ( splitted_key[3].decrypt() == 0x76357332 );

    CryptoBitset<128> v(CryptoBitset<128>::join<32>(ctxt, splitted_key));
    std::array<uint8_t, 16> resultantJoin = bitsetToArray<uint8_t>(v.decrypt());

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( key[i] == resultantJoin[i] );

    auto splitted_key2 = encrypted_key.split<5>();
    // 128/5 leads to five chunks of size 25 and a chunk of size 3
    // so 6 chunks in total
    REQUIRE ( splitted_key2.size() == 6 );
    REQUIRE (
        splitted_key2[0].decrypt() == (((0b1 & 0x61) << 24) + 0x4B2D47) 
    );
    REQUIRE (
        splitted_key2[1].decrypt() == (((0x53 & 0b11) << 23) + (0x6450 << 7) + (0x61 >> 1)) 
    );
    REQUIRE (
        splitted_key2[2].decrypt() == (((0x6B & 0b111) << 22) + (0x5667 << 6) + (0x53 >> 2)) 
    );
    REQUIRE (
        splitted_key2[3].decrypt() == (((0x32 & 0b1111) << 21) + (0x7058 << 5) + (0x6B >> 3))
    );
    REQUIRE (
        splitted_key2[4].decrypt() == (((0x76 & 0b11111) << 20) + (0x3573 << 4) + (0x32 >> 4))
    );
    REQUIRE (
        splitted_key2[5].decrypt() == (0x76 >> 5)
    );

    CryptoBitset<128> u(CryptoBitset<128>::join<25>(ctxt, splitted_key2));
    std::array<uint8_t, 16> resultantJoin2 = bitsetToArray<uint8_t>(u.decrypt());

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( key[i] == resultantJoin2[i] );
}


TEST_CASE("AES-128 SubBytes", "[Test16]")
{
    BitEncryptionContext ctxt;

    static std::array<uint8_t, 256> sboxForward = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16
    };

    static std::array<uint8_t, 256> sboxInverse = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
        0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
        0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
        0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
        0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
        0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
        0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
        0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
        0x55, 0x21, 0x0c, 0x7d
    };

    static std::array<std::array<uint8_t, 16>, 16> testValue;

    // load testValue with 0x00, 0x01, 0x02, ..., 0xff
    for (unsigned  i = 0; i < 16; i++)
        for (unsigned j = 0; j < 16; j++)
            testValue[i][j] = static_cast<uint8_t>(i*16+j);

    std::vector<CryptoBitset<128>> vec;
    vec.reserve(16);
    for (unsigned i = 0; i < 16; i++)
        vec.push_back(CryptoBitset<128>(ctxt, arrayToBitset(testValue[i])));

    for (unsigned i = 0; i < 16; i++) 
    {
        CryptoBitset<128> substitutedByte = SubBytes(vec[i]);
        std::array<uint8_t, 16> array     = bitsetToArray<uint8_t>(substitutedByte.decrypt());
        
        for (unsigned j = 0; j < 16; j++)
            REQUIRE ( array[j] == sboxForward[i*16+j] );

        substitutedByte.refresh();

        CryptoBitset<128> originByte   = InvSubBytes(substitutedByte);
        std::array<uint8_t, 16> array2 = bitsetToArray<uint8_t>(originByte.decrypt());
        
        for (unsigned j = 0; j < 16; j++)
            REQUIRE ( array2[j] == static_cast<uint8_t>(i*16+j) );
    }
}


TEST_CASE("AES-128 ShiftRows", "[Test17]")
{
    BitEncryptionContext ctxt;

    std::array<uint8_t, 16> test_array = { 
        0x2a, 0x64, 0xd5, 0xca, 0xe4, 0x4c, 0xaa, 0xed, 
        0x1f, 0x35, 0x5a, 0x37, 0x94, 0x4e, 0xf0, 0x84 
    };

    CryptoBitset<128> encryptedArray(ctxt, arrayToBitset(test_array));
    CryptoBitset<128> shiftedArray = ShiftRows(encryptedArray);
    std::array<uint8_t, 16> testArray = bitsetToArray<uint8_t, 128>(shiftedArray.decrypt());

    std::array<uint8_t, 16> verif = {
        0x2a, 0x4c, 0x5a, 0x84, 0xe4, 0x35, 0xf0, 0xca, 
        0x1f, 0x4e, 0xd5, 0xed, 0x94, 0x64, 0xaa, 0x37
    };

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( verif[i] == testArray[i] );

    shiftedArray.refresh();
    CryptoBitset<128> originalArray = InvShiftRows(shiftedArray);
    std::array<uint8_t, 16> testArray2 = bitsetToArray<uint8_t, 128>(originalArray.decrypt());

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( test_array[i] == testArray2[i] );
}

TEST_CASE("AES-128 Key Expansion", "[Test18]")
{
    BitEncryptionContext ctxt;

    std::array<uint8_t, 16> key = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76
    };

    CryptoBitset<128> encrypted_key(ctxt, arrayToBitset(key));
    std::vector<CryptoBitset<128>> u = KeyExpansion<AES_128>(encrypted_key);

    // Array of keys we should obtain when performing the Key scheduling on 
    // the 128-bit key array above
    static uint8_t verifkeys[] = {
        // 1st key = original key
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76,
        // 2nd key
        0xC9, 0xBB, 0x73, 0x42, 0x99, 0xDF, 0x20, 0x25, 
        0xCF, 0xB4, 0x78, 0x55, 0xFD, 0xC7, 0x4D, 0x23, 
        // 3rd key
        0xD, 0x58, 0x55, 0x16, 0x94, 0x87, 0x75, 0x33, 
        0x5B, 0x33, 0xD, 0x66, 0xA6, 0xF4, 0x40, 0x45, 
        // 4th key
        0xB6, 0x51, 0x3B, 0x32, 0x22, 0xD6, 0x4E, 0x01, 
        0x79, 0xE5, 0x43, 0x67, 0xDF, 0x11, 0x03, 0x22, 
        // 5th key
        0x3C, 0x2A, 0xA8, 0xAC, 0x1E, 0xFC, 0xE6, 0xAD, 
        0x67, 0x19, 0xA5, 0xCA, 0xB8, 0x08, 0xA6, 0xE8, 
        // 6th key
        0x1C, 0x0E, 0x33, 0xC0, 0x02, 0xF2, 0xD5, 0x6D, 
        0x65, 0xEB, 0x70, 0xA7, 0xDD, 0xE3, 0xD6, 0x4F,
        // 7th key
        0x2D, 0xF8, 0xB7, 0x01, 0x2F, 0x0A, 0x62, 0x6C, 
        0x4A, 0xE1, 0x12, 0xCB, 0x97, 0x02, 0xC4, 0x84, 
        // 8th key
        0x1A, 0xE4, 0xE8, 0x89, 0x35, 0xEE, 0x8A, 0xE5, 
        0x7F, 0x0F, 0x98, 0x2E, 0xE8, 0x0D, 0x5C, 0xAA, 
        // 9th key
        0x4D, 0xAE, 0x44, 0x12, 0x78, 0x40, 0xCE, 0xF7, 
        0x07, 0x4F, 0x56, 0xD9, 0xEF, 0x42, 0x0A, 0x73, 
        // 10th key
        0x7A, 0xC9, 0xCB, 0xCD, 0x02, 0x89, 0x05, 0x3A, 
        0x05, 0xC6, 0x53, 0xE3, 0xEA, 0x84, 0x59, 0x90, 
        // 11-(Nb round + 1)-th key
        0x13, 0x02, 0xAB, 0x4A, 0x11, 0x8B, 0xAE, 0x70, 
        0x14, 0x4D, 0xFD, 0x93, 0xFE, 0xC9, 0xA4, 0x03
    };

    for (size_t i = 0; i < 11; i++) {
        assert(u[i].min_noise_budget() > 0);
        std::array<uint8_t, 16> expandedkeys = bitsetToArray<uint8_t>(u[i].decrypt());

        for (size_t j = 0; j < 16; j++) {
            std::cout << "[Test18] " << "i=" << i << " j=" << j 
                      << " value we should obtain " << (unsigned) verifkeys[i*16+j] 
                      << " value we obtained "      << (unsigned) expandedkeys[j] 
                      << std::endl;

            REQUIRE ( expandedkeys[j] == verifkeys[i*16+j] );
        }
    }
}

TEST_CASE("Check AES AddRoundKey Phase", "[Test19]")
{
}

TEST_CASE("Check AES MixColumn", "[Test20]")
{
    BitEncryptionContext ctxt;

    const ClearBit  a(0b0);
    const ClearBit  b(0b1);
    const CryptoBit c(ctxt, 0b0);
    const CryptoBit d(ctxt, 0b1);
    
    CryptoBit cst = c;
    for (unsigned i = 0; i < 2; i++) {
        for (auto& cst0 : {a,b}) {
            for (auto& cst1 : {a,b}) {
                CryptoBit res(ctxt, 0b0);
                // c = 0; d = 0
                res = (cst & cst0) ^ (cst & cst1);
                REQUIRE ( (((cst.decrypt() & cst0.decode()) ^ (cst.decrypt() & cst1.decode())))
                         == (res.decrypt()) );
            }
        }
        cst = d;
    }

    /*
    ClearBitset<8> cst1(0x01), cst2(0x02), cst3(0x03), cst9(0x09), cste(0x0e), cstb(0x0b), cstd(0x0d);

    for (unsigned val = 0; val < 256; val++)
    {
        std::cout << "val=" << val << std::endl;
        for (auto& cst : {cst1, cst2, cst3, cst9, cste, cstb, cstd}) 
        {
            CryptoBitset<8> a(ctxt, val);
            CryptoBitset<8> c = HE_GF256_mul_circuit(a, cst);
            uint8_t test_function = GF256_mul_circuit(val, static_cast<uint8_t>(cst.decode().to_ulong()));
            assert(c.min_noise_budget() > 0);
            REQUIRE ( c.decrypt() == test_function );
        }
    }
    */

/*
    for (unsigned val = 0; val < 256; val++)
        for (unsigned val2 = 0; val2 < 256; val2++) {
            std::cout << "val1: " << val  << std::endl;
            std::cout << "val2: " << val2 << std::endl;
            uint8_t resultfunction = GFM_mul(val, val2, 0x11b);
            uint8_t test_function = GF256_mul_circuit(val, val2);
            CryptoBitset<8> a(ctxt, val);
            CryptoBitset<8> b(ctxt, val2);
            CryptoBitset<8> c = HE_GF256_mul(a, b);

            REQUIRE ( resultfunction == test_function );
            REQUIRE ( c.decrypt() == resultfunction );
        }
*/

    std::array<uint8_t, 16> originalArray = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
    };

    CryptoBitset<128> encryptedArray(ctxt, arrayToBitset(originalArray));
    CryptoBitset<128> mixedArray = MixColumns(encryptedArray);
    std::array<uint8_t, 16> testArray = bitsetToArray<uint8_t, 128>(mixedArray.decrypt());

    std::array<uint8_t, 16> verifArray = {
        0x02, 0x07, 0x00, 0x05, 0x06, 0x03, 0x04, 0x01, 
        0x0a, 0x0f, 0x08, 0x0d, 0x0e, 0x0b, 0x0c, 0x09
    };

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( testArray[i] == verifArray[i] );

    mixedArray.refresh();

    CryptoBitset<128> outBitset = InvMixColumns(mixedArray);
    std::array<uint8_t, 16> originalArrayExpected = bitsetToArray<uint8_t, 128>(outBitset.decrypt());

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( originalArrayExpected[i] == originalArray[i] );
}
/*
TEST_CASE("Homomorphic AES-128 Encryption & Decryption", "[Test21]")
{
    BitEncryptionContext ctxt;

    std::array<uint8_t, 16> data = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
    };

    std::array<uint8_t, 16> key = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76
    };

    CryptoBitset<128> he_clear_data(ctxt, arrayToBitset(data));
    CryptoBitset<128> he_clear_key (ctxt, arrayToBitset(key ));
    std::vector<CryptoBitset<128>> current_keys = KeyExpansion<AES_128>(he_clear_key);
    std::cout << "[Test21] (min) error on based data: " << he_clear_data.min_noise_budget() << std::endl;
    CryptoBitset<128> he_enc_data = HE_AES_Encrypt<AES_128>(he_clear_data, current_keys);

    std::array<uint8_t, 16> verif_enc = { 
        0x09, 0xec, 0x3a, 0x97, 0xe8, 0x27, 0x51, 0xb4, 
        0x2a, 0x77, 0x3f, 0x7d, 0x92, 0x5f, 0xfc, 0x4b
    };

    std::array<uint8_t, 16> enc_data = bitsetToArray<uint8_t, 128>(he_enc_data.decrypt());
    std::cout << "[Test21] (min) error on homomorphically AES-128 encrypted data: " << he_enc_data.min_noise_budget() << std::endl;
    assert(he_enc_data.min_noise_budget() != 0);

    for (unsigned k = 0; k < 16; k++) {
        REQUIRE ( enc_data[k] == verif_enc[k] );
    }

    he_enc_data.refresh();
    CryptoBitset<128> he_orig_data = HE_AES_Decrypt<AES_128>(he_enc_data, current_keys);
    std::array<uint8_t, 16> data_expected = bitsetToArray<uint8_t, 128>(he_orig_data.decrypt());

    for (unsigned k = 0; k < 16; k++) {
        REQUIRE ( data_expected[k] == data[k] );
    }
}

TEST_CASE("Homomorphic AES-192 Encryption & Decryption", "[Test22]")
{
    BitEncryptionContext ctxt;

    std::array<uint8_t, 16> data = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
    };

    std::array<uint8_t, 24> key = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76,
        0x89, 0x22, 0x41, 0x4A, 0xBB, 0xEA, 0x1A, 0x6E
    };

    CryptoBitset<128> he_clear_data(ctxt, arrayToBitset(data));
    CryptoBitset<192> he_clear_key (ctxt, arrayToBitset(key ));
    std::vector<CryptoBitset<128>> current_keys = KeyExpansion<AES_192>(he_clear_key);
    std::cout << "[Test22] (min) error on based data: " << he_clear_data.min_noise_budget() << std::endl;
    CryptoBitset<128> he_enc_data = HE_AES_Encrypt<AES_192>(he_clear_data, current_keys);

    std::array<uint8_t, 16> verif_enc = { 
        0xA4, 0x41, 0x00, 0x01, 0xB1, 0xAA, 0x7D, 0x77, 
        0xBE, 0xCB, 0x17, 0x6E, 0x92, 0x72, 0x95, 0xE9
    };

    std::array<uint8_t, 16> enc_data = bitsetToArray<uint8_t, 128>(he_enc_data.decrypt());
    std::cout << "[Test22] (min) error on homomorphically AES-192 encrypted data: : " << he_enc_data.min_noise_budget() << std::endl;
    assert(he_enc_data.min_noise_budget() != 0);

    for (unsigned k = 0; k < 16; k++) {
        REQUIRE ( enc_data[k] == verif_enc[k] );
    }

    he_enc_data.refresh();

    CryptoBitset<128> he_orig_data = HE_AES_Decrypt<AES_192>(he_enc_data, current_keys);
    std::array<uint8_t, 16> data_expected = bitsetToArray<uint8_t, 128>(he_orig_data.decrypt());

    for (unsigned k = 0; k < 16; k++) {
        REQUIRE ( data_expected[k] == data[k] );
    }
}*/

TEST_CASE("Homomorphic AES-256 Encryption & Decryption", "[Test23]")
{
    BitEncryptionContext ctxt;

    std::array<uint8_t, 16> data = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
    };

    std::array<uint8_t, 32> key256 = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76,
        0x89, 0x22, 0x41, 0x4A, 0xBB, 0xEA, 0x1A, 0x6E,
        0x3C, 0x6A, 0x6E, 0x70, 0x42, 0x32, 0x14, 0x77
    };

    CryptoBitset<128> he_clear_data(ctxt, arrayToBitset(  data));
    CryptoBitset<256> he_clear_key (ctxt, arrayToBitset(key256));
    std::vector<CryptoBitset<128>> current_keys = KeyExpansion<AES_256>(he_clear_key);
    std::cout << "[Test23] (min) error on based data: " << he_clear_data.min_noise_budget() << std::endl;
    CryptoBitset<128> he_enc_data = HE_AES_Encrypt<AES_256>(he_clear_data, current_keys);

    std::array<uint8_t, 16> verif_enc = { 
        0x0A, 0x71, 0x38, 0xF0, 0x6B, 0x3A, 0xC9, 0x4A, 
        0xAC, 0x03, 0xA0, 0x81, 0xDB, 0xC7, 0xED, 0x37
    };

    std::array<uint8_t, 16> enc_data = bitsetToArray<uint8_t, 128>(he_enc_data.decrypt());
    std::cout << "[Test23] (min) error on homomorphically AES encrypted data: " << he_enc_data.min_noise_budget() << std::endl;
    assert(he_enc_data.min_noise_budget() != 0);

    for (unsigned k = 0; k < 16; k++)
        REQUIRE ( enc_data[k] == verif_enc[k] );

    he_enc_data.refresh();

    CryptoBitset<128> he_orig_data = HE_AES_Decrypt<AES_256>(he_enc_data, current_keys);
    std::array<uint8_t, 16> data_expected = bitsetToArray<uint8_t, 128>(he_orig_data.decrypt());

    for (unsigned k = 0; k < 16; k++)
        REQUIRE ( data_expected[k] == data[k] );
}

/*
TEST_CASE("Round Performance AES", "[Bench1]")
{
    chrono::high_resolution_clock::time_point time_start, time_end;
    // 1024, 2048, 4096, 8192, 16384, or 32768
    std::array<BitEncryptionContext, 4> testCtxts = { 
        BitEncryptionContext(4096), BitEncryptionContext(8192), 
        BitEncryptionContext(16384), BitEncryptionContext(32768) 
    };

    for (auto& ctxt : testCtxts) 
    {
            std::array<uint8_t, 16> data = { 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
        };

        std::array<uint8_t, 16> key = {
            0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
            0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76
        };

        CryptoBitset<128> he_clear_data(ctxt, arrayToBitset(data));
        CryptoBitset<128> he_clear_key (ctxt, arrayToBitset(key ));
        std::vector<CryptoBitset<128>> current_keys = KeyExpansion<AES_128>(he_clear_key);
        
        std::cout << "[Bench1] (min) error on based data: " << he_clear_data.min_noise_budget() << std::endl;
        
        time_start = chrono::high_resolution_clock::now();
        he_clear_data = SubBytes(he_clear_data);
        std::cout << "[Bench1] (min) error after SubBytes: " << he_clear_data.min_noise_budget() << std::endl;
        //currentBlock.refresh();
        he_clear_data = ShiftRows(he_clear_data);
        std::cout << "[Bench1] (min) error after ShiftRows: " << he_clear_data.min_noise_budget() << std::endl;
        he_clear_data = MixColumns(he_clear_data);
        std::cout << "[Bench1] (min) error after MixColumns: " << he_clear_data.min_noise_budget() << std::endl;
        //currentBlock.refresh();
        he_clear_data = AddRoundKey(he_clear_data, current_keys[0]);
        std::cout << "[Bench1] (min) error after AddRoundKey: " << he_clear_data.min_noise_budget() << std::endl;
        
        time_end = chrono::high_resolution_clock::now();
        chrono::milliseconds time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
        std::cout << "1 AES round Done in [" << time_diff.count() << " milliseconds] with " << endl;
    }
}


TEST_CASE("Homomorphic Key-switching on AES-128", "[Test24]")
{
    BitEncryptionContext ctxt;

    // The underlying plain data used in this test is:
    // data0 = {
    //    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    //    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F 
    // };

    // First 128-bit key
    std::array<uint8_t, 16> key_0 = {
        0x47, 0x2D, 0x4B, 0x61, 0x50, 0x64, 0x53, 0x67,
        0x56, 0x6B, 0x58, 0x70, 0x32, 0x73, 0x35, 0x76 
    };

    // Encrypted data0 with AES-128 with key_0
    std::array<uint8_t, 16> aes_data_key_0 = { 
        0x09, 0xEC, 0x3A, 0x97, 0xE8, 0x27, 0x51, 0xB4, 
        0x2A, 0x77, 0x3F, 0x7D, 0x92, 0x5F, 0xFC, 0x4B
    };

    // Second 128-bit key
    std::array<uint8_t, 16> key_1 = {
        0x89, 0x22, 0x41, 0x4A, 0xBB, 0xEA, 0x1A, 0x6E,
        0x3C, 0x6A, 0x6E, 0x70, 0x42, 0x32, 0x14, 0x77
    };

    // Expected result of the key-switching key_0 -> key_1
    std::array<uint8_t, 16> exp_aes_data_key_1 = {
        0x89, 0xC1, 0x8B, 0x7C, 0xB4, 0x4B, 0x34, 0x04, 
        0x76, 0x97, 0x58, 0x9D, 0x60, 0xE7, 0xD5, 0xC7
    };

    CryptoBitset<128> he_aes_enc_k0(ctxt, 
                                    arrayToBitset(aes_data_key_0));

    CryptoBitset<128> he_k0(ctxt, arrayToBitset(key_0));
    CryptoBitset<128> he_k1(ctxt, arrayToBitset(key_1));

    CryptoBitset<128> result = HE_AES_Keyswitching<AES_128>(he_aes_enc_k0, he_k0, he_k1);
    std::cout << "[Test24] (min) error on homomorphicall AES key-switched data:  " << result.min_noise_budget() << std::endl;
    std::array<uint8_t, 16> aes_data_key_1 = bitsetToArray<uint8_t, 128>(result.decrypt());

    for (unsigned i = 0; i < 16; i++)
        REQUIRE ( aes_data_key_1[i] == exp_aes_data_key_1[i] );
}*/

/*
#include "encryptionlayerSIMD.hpp"

TEST_CASE("Packed Vectors", "[Test25]")
{
    PackedBitsEncryptionContext<4096> ctxt;
    std::vector<uint64_t> vec;
    PackedCryptoBits<4096> a(ctxt, vec = { 0b0, 0b0, 0b1, 0b1 });
    PackedCryptoBits<4096> b(ctxt, vec = { 0b0, 0b1, 0b0, 0b1 });

    // Test XOR
    PackedCryptoBits<4096> c = a ^ b;
    std::vector<uint64_t> res = c.decrypt();

    REQUIRE ((res[0] == 0b0 && res[1] == 0b1 &&
              res[2] == 0b1 && res[3] == 0b0));
    for (size_t i = 4; i < c.nb_elements(); i++)
        REQUIRE (( res[i] == 0 ));

    // Test AND    
    PackedCryptoBits<4096> d = a & b;
    res = d.decrypt();

    REQUIRE ((res[0] == 0b0 && res[1] == 0b0 &&
              res[2] == 0b0 && res[3] == 0b1));
    for (size_t i = 4; i < d.nb_elements(); i++)
        REQUIRE (( res[i] == 0 ));
    
    // Test OR    
    PackedCryptoBits<4096> e = a | b;
    res = e.decrypt();

    REQUIRE ((res[0] == 0b0 && res[1] == 0b1 &&
              res[2] == 0b1 && res[3] == 0b1));
    for (size_t i = 4; i < e.nb_elements(); i++)
        REQUIRE (( res[i] == 0 ));

    // Test NOT
    PackedCryptoBits<4096> f(ctxt, 0b0);
    res = (!f).decrypt();
    for (size_t i = 0; i < f.nb_elements(); i++)
        REQUIRE (( res[i] == 1 ));
    
    res = (!!f).decrypt();
    for (size_t i = 0; i < f.nb_elements(); i++)
        REQUIRE (( res[i] == 0 ));
    
    // Test Set to 0 & 1
    PackedCryptoBits<4096> g(ctxt, 0b0);
    
    g = g.set_to_1();
    res = g.decrypt();
    for (size_t i = 0; i < f.nb_elements(); i++)
        REQUIRE (( res[i] == 1 ));
    
    res = g.set_to_0().decrypt();
    for (size_t i = 0; i < f.nb_elements(); i++)
        REQUIRE (( res[i] == 0 ));

    std::vector<uint64_t> packedVector(4096, 0u);
    // [ 0, 0, ..., 0, 1 ]
    // [ 1, 1, ..., 1, 1 ]
    for (size_t i = 2047; i < 4096; i++)
        packedVector[i] = 1;

    std::vector<uint64_t> packedVector2(4096, 1u);
    // [ 1, 1, ..., 1, 1 ]
    // [ 1, 0, ..., 0, 0 ]
    for (size_t i = 2049; i < 4096; i++)
        packedVector2[i] = 0;

    PackedCryptoBits<4096> h(ctxt, packedVector);
    PackedCryptoBits<4096> j(ctxt, packedVector2);
    PackedCryptoBits<4096> xor_hj = (h ^ j);
    PackedCryptoBits<4096> and_hj = (h & j);
    PackedCryptoBits<4096> or_hj  = (h | j);

    res = xor_hj.decrypt();
    // [ 0, 0, ..., 0, 1 ]
    // [ 1, 1, ..., 1, 1 ]
    //         XOR
    // [ 1, 1, ..., 1, 1 ]
    // [ 1, 0, ..., 0, 0 ]
    //          =
    // [ 1, 1, ..., 1, 0 ]
    // [ 0, 1, ..., 1, 1 ]
    for (size_t i = 0; i < 2047; i++) REQUIRE ( res[i] == 1 );
    REQUIRE (( res[2047] == 0 && res[2048] == 0 ));
    for (size_t i = 2049; i < 4096; i++) REQUIRE ( res[i] == 1 );

    res = or_hj.decrypt();
    // [ 0, 0, ..., 0, 1 ]
    // [ 1, 1, ..., 1, 1 ]
    //         OR
    // [ 1, 1, ..., 1, 1 ]
    // [ 1, 0, ..., 0, 0 ]
    //          =
    // [ 1, 1, ..., 1, 1 ]
    // [ 1, 1, ..., 1, 1 ]
    for (size_t i = 0; i < 4096; i++) 
        REQUIRE ( res[i] == 1 );

    res = and_hj.decrypt();
    // [ 0, 0, ..., 0, 1 ]
    // [ 1, 1, ..., 1, 1 ]
    //         AND
    // [ 1, 1, ..., 1, 1 ]
    // [ 1, 0, ..., 0, 0 ]
    //          =
    // [ 0, 0, ..., 0, 1 ]
    // [ 1, 0, ..., 0, 0 ]
    for (size_t i = 0; i < 2047; i++) REQUIRE ( res[i] == 0 );
    REQUIRE (( res[2047] == 1 && res[2048] == 1 ));
    for (size_t i = 2049; i < 4096; i++) REQUIRE ( res[i] == 0 );
}*/