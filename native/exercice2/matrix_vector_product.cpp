#include "matrix_vector_product.hpp"

static Plaintext CreateMaskBatch(EncryptionParameters& parms) {
    SEALContext context(parms); BatchEncoder batch_encoder(context); Plaintext mask;
    size_t slot_count = batch_encoder.slot_count();
    std::vector<uint64_t> pod_matrix(slot_count, 0ULL);
    // we only initialize the first value at one this gives us :
    //  [ 1, 0, 0, 0, 0, 0, ..., 0 ] [ 0, 0, 0, 0, 0, 0, ..., 0 ]
    pod_matrix[0] = 1ULL; 
    batch_encoder.encode(pod_matrix, mask); 
    return mask;
}

Ciphertext InnerProductV2(EncryptionParameters& parms, Evaluator & eval, const Ciphertext& vec1, const 
                          Ciphertext& vec2, GaloisKeys& gk, RelinKeys & rk, size_t NbElem = 0ULL)
{
    // If the number of batched values is not given, we assume that the vector is at most of size 
    // poly_modulus_degree/2
    if (NbElem == 0) NbElem = parms.poly_modulus_degree()/2;

    Ciphertext out;
    // SIMD types multiplication
    eval.multiply(vec1, vec2, out);
    // NOTE: it is mandatory to relinearize as the multiplication will give a cipher of size > 2, and 
    // the rotation could only be done if the size is equal to 2
    eval.relinearize_inplace(out, rk);

    // Generate a "mask" batch
    Plaintext mask = CreateMaskBatch(parms);

    Ciphertext shiftedvector(out); Ciphertext temp;
    
    for (size_t i = 1; i < NbElem; i++) {
        // (Example) first iteration : let shiftedvector, an arbitrary vector encoded in the batched 
        // matrix shiftedvector = [ a, b, c, d, e, f, ..., z ]
        //                        [ 0, 0, 0, 0, 0, 0, ..., 0 ]

        // We shift the matrix by the rows (once at each iteration) 
        // shiftedvector = [ b, c, d, e, f, g, ..., a ]
        //                 [ 0, 0, 0, 0, 0, 0, ..., 0 ]
        eval.rotate_rows_inplace(shiftedvector, 1, gk);
        // The mask multiplication gives us temp = [ b, 0, 0, 0, 0, 0, ..., 0 ]
        //                                         [ 0, 0, 0, 0, 0, 0, ..., 0 ]
        eval.multiply_plain(shiftedvector, mask, temp);
        // [ a, b, c, d, e, f, ..., z ] [ 0, 0, 0, 0, 0, 0, ..., 0 ]
        //                 +
        // [ b, 0, 0, 0, 0, 0, ..., 0 ] [ 0, 0, 0, 0, 0, 0, ..., 0 ]
        //                 =
        // [a+b, b, c, d, e, f, ..., z ] [ 0, 0, 0, 0, 0, 0, ..., 0 ]
        eval.add_inplace(out, temp);
        // We repeat this process until we have the sum a+b+c+...+z in 'out[0]'
    }
    // Finally, we mask the out cipher NOTE: we could do that before...
    eval.multiply_plain_inplace(out, mask); return out;
}

std::vector<Ciphertext> matrixVectorProduct(EncryptionParameters& parms, 
                                            Evaluator & eval, 
                                            const std::vector<Ciphertext>& matrix, 
                                            const Ciphertext& vec,
                                            GaloisKeys& gk, 
                                                    RelinKeys & rk, 
                                            size_t NbElem = 0ULL)
{ 
	std::vector<Ciphertext> out(matrix.size()); 
	Ciphertext temp; 
	for (size_t i=0; i<matrix.size(); i++) {
		temp = InnerProductV2(parms, eval, matrix[i], vec, gk, rk, NbElem); 
		out[i] = temp;
	}
	return out;

}

// https://github.com/microsoft/SEAL-Demo/blob/master/CloudFunctionsDemo/ClientBasedFunctions/ClientBasedFunctions/MatrixProduct.md

// Thinking: generalization of this method to non square matrix...
// [ a b c ] [ A ]
// [ d e f ] [ B ]
// [ g h i ] [ C ]
// [ j k l ]
//
// cyclicDiagsMatrix = [ a e i j ]
//                     [ b f g k ]
//                     [ c d h l ]
//
// (element-wise)
// [ a e i j ] * [ A B C A B C ] = [ aA eB iC jA ]
// [ b f g k ] * [ B C A B C A ] = [ bB fC gA kB ]
// [ c d h l ] * [ C A B C A B ] = [ cC dA hB lC ]
//
// [ aA eB iC jA] + [ bB fC gA kB] + [ cC dA hB lC]
// = [ aA+bB+cC eB+fC+dA iC+gD+hA jA+kB+lC]
Ciphertext squareMatrixVectorProduct(EncryptionParameters& params,
                                     Evaluator& eval,
                                     const std::vector<Ciphertext>& cyclicDiagsMatrix,
                                     const Ciphertext& vec,
                                     size_t realVectorSize,
                                     GaloisKeys& gk)
{
    if (cyclicDiagsMatrix.size() > params.poly_modulus_degree()/2)
        throw "can't execute this function with theses types of parameters";

    // cyclicDiagsMatrix.size() => number of line in the matrix
    // realVectorSize => number of coeff in the vector / number of column in
    // the matrix if squared
    if (cyclicDiagsMatrix.size() != realVectorSize)
        throw "illegal size of matrix and/or vector";

    // Square matrix-vector multiplication:
    // [ a b c ] [ A ]   [ aA + bB + cC ]
    // [ d e f ] [ B ] = [ dA + eB + fC ]
    // [ g h i ] [ C ]   [ gA + hB + iC ]
    // 
    // 1) We assume that the first step is already done, i.e. cyclicDiagsMatrix
    // is equivalent to:
    // cyclicDiagsMatrix = [ a e i ]
    //                     [ b f g ]
    //                     [ c d h ]
    //
    // 2) Then, we multiply (element-wise) the row vectors of the matrix with 
    // the rotated vector:
    // [ a e i ] * [ A B C ] = [ aA eB iC ]
    // [ b f g ] * [ B C A ] = [ bB fC gA ]
    // [ c d h ] * [ C A B ] = [ cC dA hB ]
    // 
    // 3) Finally, we sum all the resulting vectors:
    // [ aA eB iC ] + [ bB fC gA ] + [ cC dA hB ] = [ aA+bB+cC, eB+fC+dA, iC+gA+hB ]

    std::vector<Ciphertext> multResult(cyclicDiagsMatrix.size());
    Ciphertext rotatedVector(vec);

    // Step 2)
    for (size_t i = 0; i < cyclicDiagsMatrix.size(); i++) {
        // [a e i] * [A B C] = [aA eB iC], [b f g] * [B C A] = [bB fC gA], ...
        eval.multiply(cyclicDiagsMatrix[i], rotatedVector, multResult[i]);
        // [ A B C ] -> [ B C A ] -> [ C A B ] -> ...

        Plaintext mask = CreateMaskBatch(params);
        Ciphertext resultingCoeff;
        eval.multiply_plain(rotatedVector, mask, resultingCoeff);
        eval.rotate_rows_inplace(resultingCoeff, static_cast<int>(i+1-realVectorSize), gk);
        eval.rotate_rows_inplace(rotatedVector, 1, gk);
        eval.add_inplace(rotatedVector, resultingCoeff);
    }

    Ciphertext out(multResult[0]);
    // Step 3) [aA eB iC] + [bB fC gA] + [cC dA hB]
    for (size_t i = 1; i < multResult.size(); i++)
        eval.add_inplace(out, multResult[i]);

    return out;
}