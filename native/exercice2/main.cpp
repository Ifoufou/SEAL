#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "matrix_vector_product.hpp"

TEST_CASE("Matrix Vector Multiplication", "Using the inner product")
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

    Plaintext plain_matrix_v1;
    Plaintext plain_matrix_v2;
    Plaintext plain_matrix_v3;
    Plaintext plain_matrix_v4;
    Plaintext plain_vec;
    Ciphertext encrypted_vec;

    std::vector<uint64_t> vec(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    vec[1] = 1ULL;
    vec[2] = 2ULL;
    vec[3] = 3ULL;

    print_matrix(vec, 1);

    std::vector<uint64_t> matrix_v1(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    matrix_v1[1] = 1ULL;
    matrix_v1[2] = 2ULL;
    matrix_v1[3] = 3ULL;

    std::vector<uint64_t> matrix_v2(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    matrix_v2[1] = 1ULL;
    matrix_v2[2] = 2ULL;
    matrix_v2[3] = 3ULL;

    std::vector<uint64_t> matrix_v3(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    matrix_v3[1] = 1ULL;
    matrix_v3[2] = 2ULL;
    matrix_v3[3] = 3ULL;

    std::vector<uint64_t> matrix_v4(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    matrix_v4[1] = 1ULL;
    matrix_v4[2] = 2ULL;
    matrix_v4[3] = 3ULL;

    batch_encoder.encode(vec, plain_vec);

    batch_encoder.encode(vec, plain_matrix_v1);
    batch_encoder.encode(vec, plain_matrix_v2);
    batch_encoder.encode(vec, plain_matrix_v3);
    batch_encoder.encode(vec, plain_matrix_v4);

    std::vector<Ciphertext> matrix(4);

    encryptor.encrypt(plain_vec, encrypted_vec);
    encryptor.encrypt(plain_matrix_v1, matrix[0]);
    encryptor.encrypt(plain_matrix_v2, matrix[1]);
    encryptor.encrypt(plain_matrix_v3, matrix[2]);
    encryptor.encrypt(plain_matrix_v4, matrix[3]);

    std::vector<Ciphertext> matrix_vector_product = matrixVectorProduct(parms, evaluator, matrix, encrypted_vec, galois_keys,relin_keys,4);

    std::vector<Plaintext> issou(4);
    std::vector<std::vector<uint64_t>> out(4);
    for (size_t i = 0; i<4; i++)
    {
        decryptor.decrypt(matrix_vector_product[i], issou[i]);
        batch_encoder.decode(issou[i], out[i]);
        print_matrix(out[i], 1);
    }

    REQUIRE( (out[0][0] == 14 &&
              out[1][0] == 14 &&
              out[2][0] == 14 &&
              out[3][0] == 14) );
}

TEST_CASE("Second Matrix Vector Multiplication", "Efficient implementation")
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

    Plaintext plain_vec;
    Ciphertext encrypted_vec;

    std::vector<uint64_t> vec(slot_count, 0ULL);
    // vec1[0] <-- 0ULL; 
    vec[1] = 1ULL;
    vec[2] = 2ULL;
    vec[3] = 3ULL;

    batch_encoder.encode(vec, plain_vec);
    std::vector<Ciphertext> matrix(4);
    encryptor.encrypt(plain_vec, encrypted_vec);

    std::vector<uint64_t> issou = {
         1,  2,  3,  4,
         5,  6,  7,  8,
         9, 10, 11, 12, 
        13, 14, 15, 16
    };

    size_t columnSize = 4;

    // conversion "standard" matrix -> cyclic diagonal matrix
    std::vector<uint64_t> cyclicmat = matrixToCyclicDiagsMatrix(issou, columnSize);

    print_arbitrary_matrix(issou, columnSize);
    print_arbitrary_matrix(cyclicmat, columnSize);

    size_t nbRow = cyclicmat.size()/columnSize;
    std::vector<Plaintext>  plain_matrix(nbRow);
    std::vector<Ciphertext> cipher_matrix(nbRow);

    for (size_t i = 0; i < nbRow; i++)
    {
        std::vector<uint64_t> row_vector(slot_count, 0ULL);
        for (size_t j = 0; j < columnSize; j++) {
            row_vector[j] = cyclicmat[i*columnSize+j];
            std::cout << row_vector[j] << " ";
        }
        std::cout << std::endl;
        batch_encoder.encode(row_vector, plain_matrix[i]);
        encryptor.encrypt(plain_matrix[i], cipher_matrix[i]);
    }

    Ciphertext rotatedVector(encrypted_vec);
    print_matrix(vec, 4);
    evaluator.rotate_rows_inplace(rotatedVector, 1, galois_keys);
    decryptor.decrypt(encrypted_vec, plain_vec);
    std::vector<uint64_t> test;
    batch_encoder.decode(plain_vec, test);

    print_matrix(test, 4);

    Ciphertext cp = squareMatrixVectorProduct(parms, 
                                              evaluator,
                                              cipher_matrix,
                                              encrypted_vec,
                                              columnSize,
                                              galois_keys);
    
    decryptor.decrypt(cp, plain_vec);
    std::vector<uint64_t> out;
    batch_encoder.decode(plain_vec, out);

    /*REQUIRE( (out[0] == 20 &&
              out[1] == 45 &&
              out[2] == 68 &&
              out[3] == 92) );*/

    std::cout << out[0] << " " <<
                 out[1] << " " <<
                 out[2] << " " <<
                 out[3] << std::endl;
}