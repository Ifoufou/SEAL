#include "outerproduct.hpp"

std::vector<Ciphertext> OuterProductV1(Evaluator              & eval,
                                       std::vector<Ciphertext>& vec1,
                                       std::vector<Ciphertext>& vec2)
{
    // Outer-product, product of the form :
    // [x_1,]   
    // [x_2,] *  [ y_1, y_2, ..., y_m ] = Matrix of size n*m
    // [...,]       
    // [x_n ]

    // We initialize the matrix container of size n*m.
    // NOTE: we are going to store the matrix coefficients lines by lines.
    std::vector<Ciphertext> matrix(vec1.size()*vec2.size());
    size_t rowSize = vec2.size();

    for (size_t i = 0; i < vec1.size(); i++)
        for (size_t j = 0; j < vec2.size(); j++)
            eval.multiply(vec1[i], vec2[j], 
                          matrix[i*rowSize+j]);

    return matrix;
}

static Plaintext CreateMaskBatch(EncryptionParameters& parms)
{
    SEALContext context(parms);
    BatchEncoder batch_encoder(context);
    Plaintext mask;

    size_t slot_count = batch_encoder.slot_count();

    std::vector<uint64_t> pod_matrix(slot_count, 0ULL);
    // We only initialize the first value at one
    // This gives us :
    //  [ 1,  0,  0,  0,  0,  0, ...,  0 ]
    //  [ 0,  0,  0,  0,  0,  0, ...,  0 ]
    pod_matrix[0] = 1ULL;
    batch_encoder.encode(pod_matrix, mask);
    return mask;
}

// For a given batched vector (encrypted in a Ciphertext): 
// [ a, b, c, d, ..., z ]
// [ 0, 0, 0, 0, ..., 0 ]
// This function returns the partial "splatted" vector, which is:
//               (nbSplat-1)
//                    |
// [ a, a, a, a, ..., a, 0, ..., 0 ]
// [ 0, 0, 0, 0, ..., 0, 0, ..., 0 ]
Ciphertext PartialSplatCipher(EncryptionParameters params,
                              Evaluator &          eval,
                              Ciphertext&          vec,
                              GaloisKeys&          gk,
                              size_t               nbSplat = 0ULL)
{
    size_t rowSize = params.poly_modulus_degree()/2;
    if (nbSplat == 0 || nbSplat > rowSize)
        // In this case, it's gonna take quite a long time...
        nbSplat = rowSize;

    // Basic algorithm:
    //  out = masked(vec)
    //  tmp = out
    //  repeat until we cover all the partial coefficients
    //      tmp = rightShift_rows(tmp, 1)
    //      out <= out + tmp
    //  return out
    
    Plaintext mask = CreateMaskBatch(params);
    Ciphertext out(vec);
    // out = masked(vec)
    eval.multiply_plain_inplace(out, mask);

    Ciphertext tmp(out);

    for (size_t i = 0; i < nbSplat-1; i++) 
    {
        // (Example) first iteration :
        // out = [ a, 0, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        // tmp = [ a, 0, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        // 
        // rotation one step to the right at each iteration
        // tmp = [ 0, a, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        eval.rotate_rows_inplace(tmp, -1, gk);
        // out = [ a, 0, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        //                +
        // tmp = [ 0, a, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        //                =
        // out = [ a, a, 0, 0, ..., 0 ]
        //       [ 0, 0, 0, 0, ..., 0 ]
        eval.add_inplace(out, tmp);
        // ...
    }
    return out;
}

std::vector<Ciphertext> OuterProductV2(EncryptionParameters params,
                                       Evaluator       &    eval,
                                       const Ciphertext&    vec1,
                                       const Ciphertext&    vec2,
                                       GaloisKeys      &    gk,
                                       size_t               vec1Size,
                                       size_t               vec2Size)
{
    // Here, we deal with vectors as a unitary entity, so we can't access directly
    // to one of their elements. So, vec1[i] and vec2[i] are prohibited!
    // The algorithm is still the same: we have to make the following computation
    //
    // [ x_1 ]   
    // [ x_2 ] *  [ y_1, y_2, ..., y_m ] = Matrix of size n*m
    // [ ... ]       
    // [ x_n ]
    //
    // One idea is to "splat" (SIMD vocabulary, it means broadcasting the value
    // across all elements of the vector) all x_i values into a vector.
    // i.e. 
    // x_i (scalar) becomes [ x_i, x_i, x_i, ..., x_i ] (vector of size m)
    //
    // Then, we could use the (batch/SIMD) multiplication, which is element-wise.
    // Right below, we use the symbol ** to denote this particular operation:
    // 
    // z_i = [ x_i_1, x_i_2, ..., x_i_m ] ** [ y_1, y_2, ..., y_m ]
    //
    // The final matrix Z will be formed of all the z_i as the following:
    //
    //     [ z_1 ]
    // Z = [ z_2 ]
    //     [ ... ]
    //     [ z_n ]

    size_t pmd = params.poly_modulus_degree()/2;
    // TODO: (vec1Size > pmd) --> illegal argument
    if (vec1Size == 0 || vec1Size > pmd)
        // In this case, it's gonna take quite a long time...
        vec1Size = pmd;

    if (vec2Size == 0 || vec2Size > pmd)
        // same...
        vec2Size = pmd;
    
    // Initialization of the matrix of vec1Size row vectors
    std::vector<Ciphertext> Z(vec1Size);

    Ciphertext vec1_copy(vec1);
    
    Ciphertext splatvector(PartialSplatCipher(params, eval, vec1_copy, gk, vec2Size));
    eval.multiply(splatvector, vec2, Z[0]);

    for (size_t i = 1; i < vec1Size; i++) {
        // (1) Computation of the x_i (partial) splat vector
        eval.rotate_rows_inplace(vec1_copy, 1, gk);
        splatvector = PartialSplatCipher(params, eval, vec1_copy, gk, vec2Size);
        // (2) Element-wise multiplication
        eval.multiply(splatvector, vec2, Z[i]);
    }
    return Z;
}