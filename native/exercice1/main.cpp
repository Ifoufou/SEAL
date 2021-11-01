#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "innerproduct.hpp"
#include "outerproduct.hpp"

TEST_CASE("Computation of the inner product of few vectors (one cipher for each scalar)", "[innerproductV1]" ) 
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // result storage
    Ciphertext res;
    Plaintext  out;
    size_t ip = 0ULL;

    std::vector<uint64_t> vec1 = {  4 };
    std::vector<uint64_t> vec2 = { 99 };

    std::vector<Ciphertext> ciphervec1(vec1.size());
    std::vector<Ciphertext> ciphervec2(vec2.size());

    for (size_t i = 0; i < vec1.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec1[i])), 
                          ciphervec1[i]);

    for (size_t i = 0; i < vec2.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec2[i])), 
                          ciphervec2[i]);

    // Compute homomorphically the inner product of two ciphers (vectors)
    // [ 4 ] * [ 99 ]
    res = InnerProductV1(evaluator, ciphervec1, ciphervec2);
    decryptor.decrypt(res, out);
    ip = std::stoul(out.to_string(), nullptr, 16);

    std::cout << "InnerProductV1" << std::endl;
    std::cout << "[ "   << vec1[0] << " ] " 
              << "* [ " << vec2[0] << " ] = " << ip << std::endl;

    REQUIRE( ip == 396 );

    std::vector<uint64_t> vec3 = { 2, 4, 8 };
    std::vector<uint64_t> vec4 = { 2, 3, 6 };

    std::vector<Ciphertext> ciphervec3(vec3.size());
    std::vector<Ciphertext> ciphervec4(vec4.size());

    for (size_t i = 0; i < vec3.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec3[i])), 
                          ciphervec3[i]);

    for (size_t i = 0; i < vec4.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec4[i])), 
                          ciphervec4[i]);

    res = InnerProductV1(evaluator, ciphervec3, ciphervec4);
    decryptor.decrypt(res, out);

    ip = std::stoul(out.to_string(), nullptr, 16);

    std::cout << "[ " << vec3[0] << ", " << vec3[1] << ", " << vec3[2] << " ]" << " * "
              << "[ " << vec4[0] << ", " << vec4[1] << ", " << vec4[2] << " ] = " << ip << std::endl;

    REQUIRE( ip == 64 );

    std::cout << std::endl;
}

TEST_CASE("Computation of the inner product of few vectors (one cipher for each vector)", "[innerproductV2]" ) 
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count/2;

    Plaintext plain_vec1;
    Plaintext plain_vec2;
    Ciphertext encrypted_vec1;
    Ciphertext encrypted_vec2;
    std::vector<uint64_t> out;

    std::vector<uint64_t> vec1(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    vec1[1] = 1ULL;
    vec1[2] = 2ULL;
    vec1[3] = 3ULL;

    std::vector<uint64_t> vec2(slot_count, 0ULL);
    vec2[0] = 4ULL;
    vec2[1] = 5ULL;
    vec2[2] = 6ULL;
    vec2[3] = 7ULL;

    batch_encoder.encode(vec1, plain_vec1);
    batch_encoder.encode(vec2, plain_vec2);

    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    Ciphertext innerProduct = InnerProductV2(parms, evaluator, 
                                             encrypted_vec1, 
                                             encrypted_vec2, 
                                             galois_keys,
                                             relin_keys,
                                             4);

    decryptor.decrypt(innerProduct, plain_vec1);
    batch_encoder.decode(plain_vec1, out);
    REQUIRE( out[0] == 38 );

    std::cout << "InnerProductV2" << std::endl;
    std::cout << "[ " << vec1[0] << ", " << vec1[1] << ", " << vec1[2] << ", " << vec1[3] << " ]" << " * "
              << "[ " << vec2[0] << ", " << vec2[1] << ", " << vec2[2] << ", " << vec2[3] << " ] = " << out[0] << std::endl;
    std::cout << "with the underlying 2-by-N/2 matrix representation:" << std::endl;
    print_matrix(vec1, row_size);
    std::cout << "            *";
    print_matrix(vec2, row_size);
    std::cout << "            =";
    print_matrix(out, row_size);
}

TEST_CASE("Computation of the outer product of few vectors (one cipher for each element)", "[outerproductV1]" ) 
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext  context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    std::vector<uint64_t> vec1 = { 2, 4, 8 };
    std::vector<uint64_t> vec2 = { 2, 3, 6 };

    std::vector<Ciphertext> ciphervec1(vec1.size());
    std::vector<Ciphertext> ciphervec2(vec2.size());

    for (size_t i = 0; i < vec1.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec1[i])), 
                          ciphervec1[i]);
    for (size_t i = 0; i < vec2.size(); i++)
        encryptor.encrypt(Plaintext(uint64_to_hex_string(vec2[i])), 
                          ciphervec2[i]);

    std::vector<Ciphertext> op = OuterProductV1(evaluator, ciphervec1, ciphervec2);
    std::vector<Plaintext>  vec_encoded(op.size());
    std::vector<uint64_t>   vec_out(op.size());

    for (size_t i = 0; i < op.size(); i++) {
        decryptor.decrypt(op[i], vec_encoded[i]);
        vec_out[i] = std::stoul(vec_encoded[i].to_string(), nullptr, 16);
    }

    REQUIRE( (vec_out[0] ==  4 && vec_out[1] ==  6 && vec_out[2] == 12 &&
              vec_out[3] ==  8 && vec_out[4] == 12 && vec_out[5] == 24 &&
              vec_out[6] == 16 && vec_out[7] == 24 && vec_out[8] == 48) );

    std::cout << "OuterProductV1" << std::endl;
    std::cout << "[ " << vec1[0] << ", " << std::endl
              << "  " << vec1[1] << ", " << std::endl
              << "  " << vec1[2] << " ]" << " * "
              << "[ " << vec2[0] << ", " << vec2[1] << ", " << vec2[2] << " ]" << std::endl
              << "    =" << std::endl;
    print_arbitrary_matrix(vec_out, vec2.size());
}

TEST_CASE("Computation of the outer product of few vectors (one cipher for each vector)", "[outerproductV2]" )
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext  context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count/2;

    Plaintext plain_vec1;
    Plaintext plain_vec2;
    Ciphertext encrypted_vec1;
    Ciphertext encrypted_vec2;

    std::vector<uint64_t> vec1(slot_count, 0ULL);
    vec1[1] = 1ULL;
    vec1[2] = 2ULL;
    vec1[3] = 3ULL;

    std::vector<uint64_t> vec2(slot_count, 0ULL);
    vec2[0] = 4ULL;
    vec2[1] = 5ULL;
    vec2[2] = 6ULL;
    vec2[3] = 7ULL;

    // "real" size of vec1
    size_t real_colum_size = 4;
    // "real" size of vec2
    size_t real_row_size = 4;

    batch_encoder.encode(vec1, plain_vec1);
    batch_encoder.encode(vec2, plain_vec2);

    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    std::cout << "OuterProductV2" << std::endl;
    std::cout << "[ " << vec1[0] << ", " << std::endl
              << "  " << vec1[1] << ", " << std::endl
              << "  " << vec1[2] << ", " << std::endl
              << "  " << vec1[3] << " ]" << " * "
              << "[ " << vec2[0] << ", " << vec2[1] << ", " << vec2[2] << ", " << vec2[3] << " ]" << std::endl
              << "    =" << std::endl;

    std::vector<Ciphertext> opct = OuterProductV2(parms, evaluator, 
                                                  encrypted_vec1, encrypted_vec2, 
                                                  galois_keys,
                                                  real_colum_size, real_row_size);

    std::vector<Plaintext> oppt(opct.size());
    std::vector<std::vector<uint64_t>> vec_of_row(opct.size());

    // opct (vector<Ciphertext>) --> oppt (vector<Plaintext>) --> vec_of_row (vector<vector<uint64>>)
    for (size_t i = 0; i < opct.size(); i++) {
        decryptor.decrypt(opct[i], oppt[i]);
        batch_encoder.decode(oppt[i], vec_of_row[i]);
        std::cout << "2-by-N/2 representation of the " << i << "-th row vector of the outer-product matrix";
        print_matrix(vec_of_row[i], row_size);
    }

    std::vector<uint64_t> vec_out(real_colum_size*real_row_size);
    for (size_t i = 0; i < real_colum_size; i++)
        for (size_t j = 0; j < real_row_size; j++)
            vec_out[i*real_colum_size + j] = vec_of_row[i][j];

    REQUIRE( (vec_out[ 0] ==  0 && vec_out[ 1] ==  0 && vec_out[ 2] ==  0 && vec_out[ 3] ==  0 && 
              vec_out[ 4] ==  4 && vec_out[ 5] ==  5 && vec_out[ 6] ==  6 && vec_out[ 7] ==  7 && 
              vec_out[ 8] ==  8 && vec_out[ 9] == 10 && vec_out[10] == 12 && vec_out[11] == 14 &&
              vec_out[12] == 12 && vec_out[13] == 15 && vec_out[14] == 18 && vec_out[15] == 21) );
    
    std::cout << "reconstructed (outer-product) matrix :" << std::endl;
    print_arbitrary_matrix(vec_out, real_row_size);
}