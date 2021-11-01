#include "innerproduct.hpp"

// Complexity calculation :
// If n is the size of both vectors then
// <> n multiplications
// <> n-1 additions
Ciphertext InnerProductV1(Evaluator & eval,
                          const std::vector<Ciphertext>& vec1,
                          const std::vector<Ciphertext>& vec2) 
{
    if (vec1.size() != vec2.size())
        throw "illegal argument: incompatible size";

    std::vector<Ciphertext> product(vec1.size());

    // perform Y_i = A_i * B_i
    for (size_t i = 0; i < vec1.size(); i++)
        eval.multiply(vec1[i], vec2[i], product[i]);

    // perform out = sum(Y_i)
    Ciphertext result(product[0]);

    for (size_t i = 1; i < product.size(); i++)
        eval.add_inplace(result, product[i]);

    return result;
}

static Plaintext CreateMaskBatch(EncryptionParameters& parms)
{
    SEALContext context(parms);
    BatchEncoder batch_encoder(context);
    Plaintext mask;

    size_t slot_count = batch_encoder.slot_count();

    std::vector<uint64_t> pod_matrix(slot_count, 0ULL);
    // we only initialize the first value at one
    // this gives us :
    //  [ 1,  0,  0,  0,  0,  0, ...,  0 ]
    //  [ 0,  0,  0,  0,  0,  0, ...,  0 ]
    pod_matrix[0] = 1ULL;
    batch_encoder.encode(pod_matrix, mask);
    return mask;
}

Ciphertext InnerProductV2(EncryptionParameters& parms,
                          Evaluator & eval,
                          const Ciphertext& vec1, 
                          const Ciphertext& vec2,
                          GaloisKeys& gk,
                          RelinKeys & rk,
                          size_t NbElem = 0ULL)
{
    // If the number of batched values is not given, we assume that the vector 
    // is at most of size poly_modulus_degree/2
    if (NbElem == 0)
        NbElem = parms.poly_modulus_degree()/2;

    Ciphertext out;
    // SIMD types multiplication
    eval.multiply(vec1, vec2, out);
    // NOTE: it is mandatory to relinearize as the multiplication will give a 
    // cipher of size > 2, and the rotation could only be done if the size is
    // equal to 2
    eval.relinearize_inplace(out, rk);

    // Generate a "mask" batch
    Plaintext mask = CreateMaskBatch(parms);

    Ciphertext shiftedvector(out);
    Ciphertext temp;
    
    for (size_t i = 1; i < NbElem; i++)
    {
        // (Example) first iteration :
        // let shiftedvector, an arbitrary vector encoded in the batched matrix
        // shiftedvector = [ a,  b,  c,  d,  e,  f, ...,  z ]
        //                 [ 0,  0,  0,  0,  0,  0, ...,  0 ]

        // We shift the matrix by the rows (once at each iteration)
        // shiftedvector = [ b,  c,  d,  e,  f,  g, ...,  a ]
        //                 [ 0,  0,  0,  0,  0,  0, ...,  0 ]
        eval.rotate_rows_inplace(shiftedvector, 1, gk);
        // The mask multiplication gives us
        // temp = [ b,  0,  0,  0,  0,  0, ...,  0 ]
        //        [ 0,  0,  0,  0,  0,  0, ...,  0 ]
        eval.multiply_plain(shiftedvector, mask, temp);
        // [ a,  b,  c,  d,  e,  f, ...,  z ]
        // [ 0,  0,  0,  0,  0,  0, ...,  0 ]
        //                 +
        // [ b,  0,  0,  0,  0,  0, ...,  0 ]
        // [ 0,  0,  0,  0,  0,  0, ...,  0 ]
        //                 =
        // [a+b, b,  c,  d,  e,  f, ...,  z ]
        // [ 0,  0,  0,  0,  0,  0, ...,  0 ]
        eval.add_inplace(out, temp);
        // We repeat this process until we have the sum a+b+c+...+z in 'out[0]'
    }
    // Finally, we mask the out cipher
    // NOTE: we could do that before...
    eval.multiply_plain_inplace(out, mask);
    return out;
}