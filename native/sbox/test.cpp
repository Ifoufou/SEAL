#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "sbox.hpp"

using namespace seal;
using namespace std;

TEST_CASE("Test AND", "[Test1]" ) 
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

TEST_CASE("Test OR", "[Test2]" ) 
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

TEST_CASE("Test XOR", "[Test3]" ) 
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

TEST_CASE("Test NOT", "[Test4]" ) 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    CryptoBit c = !a;
    CryptoBit d = !b;

    REQUIRE ( c.decrypt() == 0b1 );
    REQUIRE ( d.decrypt() == 0b0 );
}

TEST_CASE("Test XNOR", "[Test5]" ) 
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

TEST_CASE("Test set to 0", "[Test6]" ) 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    REQUIRE ( a.set_to_0().decrypt() == 0b0 );
    REQUIRE ( b.set_to_0().decrypt() == 0b0 );
}

TEST_CASE("Test set to 1", "[Test7]" ) 
{
    BitEncryptionContext ctxt;

    CryptoBit a(ctxt, 0b0);
    CryptoBit b(ctxt, 0b1);

    REQUIRE ( a.set_to_1().decrypt() == 0b1 );
    REQUIRE ( b.set_to_1().decrypt() == 0b1 );
}

TEST_CASE("Encryption and Decryption via the bitfield", "[Test8]" )
{
    BitEncryptionContext ctxt;

    uint16_t inputData = 7;
    CryptoBitField<uint16_t, 5> field(ctxt, inputData);
    REQUIRE ( field.decrypt() == 7 );
    
    // 00111 -> 00110
    field[0].set_to_0();
    REQUIRE ( field.decrypt() == 6 );

    std::cout << "[Test8] (min) noise budget: " << field.min_noise_budget() << " bits"
              << std::endl;

    // 00011
    inputData = 3;
    CryptoBitField<uint16_t, 5> field2(ctxt, inputData);
    CryptoBitField<uint16_t, 5> field3 = !(field & field2);
    // 00110 & 00011 -> 00010 -> 11101
    REQUIRE ( field3.decrypt() == 29 );
}

TEST_CASE("S-Box by value check", "[Test9]" )
{
    BitEncryptionContext ctxt;

    S_Box<uint32_t, 1> sbox1(
        LUTInput(0b0) ->* LUTOutput(0b1),
        LUTInput(0b1) ->* LUTOutput(0b0)
    );

    CryptoBitField<uint32_t, 1> input_0(ctxt, 0b0);
    CryptoBitField<uint32_t, 1> input_1(ctxt, 0b1);

    CryptoBitField<uint32_t, 1> output_0 = sbox1.apply(ctxt, input_0);
    CryptoBitField<uint32_t, 1> output_1 = sbox1.apply(ctxt, input_1);

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

    CryptoBitField<uint32_t, 2> input_00(ctxt, 0b00);
    CryptoBitField<uint32_t, 2> input_01(ctxt, 0b01);
    CryptoBitField<uint32_t, 2> input_10(ctxt, 0b10);
    CryptoBitField<uint32_t, 2> input_11(ctxt, 0b11);

    CryptoBitField<uint32_t, 2> output_00 = sbox2.apply(ctxt, input_00);
    CryptoBitField<uint32_t, 2> output_01 = sbox2.apply(ctxt, input_01);
    CryptoBitField<uint32_t, 2> output_10 = sbox2.apply(ctxt, input_10);
    CryptoBitField<uint32_t, 2> output_11 = sbox2.apply(ctxt, input_11);

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
    CryptoBitField<uint32_t, 2> reversed_output_00 = sbox2.reverse(ctxt, output_00);
    // 0b10 -> 0b01
    CryptoBitField<uint32_t, 2> reversed_output_01 = sbox2.reverse(ctxt, output_01);
    // 0b01 -> 0b10
    CryptoBitField<uint32_t, 2> reversed_output_10 = sbox2.reverse(ctxt, output_10);
    // 0b00 -> 0b11
    CryptoBitField<uint32_t, 2> reversed_output_11 = sbox2.reverse(ctxt, output_11);

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

TEST_CASE("S-Box by functions check", "[Test10]" )
{
    BitEncryptionContext ctxt;

    std::function<CryptoBitField<uint32_t, 2>
                 (const CryptoBitField<uint32_t, 2>&)>
    inverter = [](const CryptoBitField<uint32_t, 2>& arg) 
    {
        return !arg;
    };

    // The inverter is its own inverse
    std::function<CryptoBitField<uint32_t, 2>
                 (const CryptoBitField<uint32_t, 2>&)>
    inverter_reverse = inverter;

    S_Box<uint32_t, 2> sbox(inverter, inverter_reverse);

    CryptoBitField<uint32_t, 2> input_00(ctxt, 0b00);
    CryptoBitField<uint32_t, 2> input_01(ctxt, 0b01);
    CryptoBitField<uint32_t, 2> input_10(ctxt, 0b10);
    CryptoBitField<uint32_t, 2> input_11(ctxt, 0b11);

    CryptoBitField<uint32_t, 2> output_00 = sbox.apply(ctxt, input_00);
    CryptoBitField<uint32_t, 2> output_01 = sbox.apply(ctxt, input_01);
    CryptoBitField<uint32_t, 2> output_10 = sbox.apply(ctxt, input_10);
    CryptoBitField<uint32_t, 2> output_11 = sbox.apply(ctxt, input_11);

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