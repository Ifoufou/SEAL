#ifndef __ENCRYPTION_LAYER_SIMD_HPP__
#define __ENCRYPTION_LAYER_SIMD_HPP__

#include <assert.h>
#include <bitset>
#include <memory>
#include "encryptionlayer.hpp"
#include "seal_include.hpp"

template <std::size_t pmd>
class PackedCryptoBits;

template <std::size_t pmd = 4096>
class PackedBitsEncryptionContext
{
    seal::EncryptionParameters _parms;
    seal::SecretKey _secret_key;
    seal::PublicKey _public_key;
    seal::RelinKeys _relin_keys;

    std::unique_ptr<seal::SEALContext>  _context; 
    std::unique_ptr<seal::BatchEncoder> _batch_encoder;
    std::unique_ptr<seal::Encryptor  >  _encryptor;
    std::unique_ptr<seal::Evaluator  >  _evaluator;
    std::unique_ptr<seal::Decryptor  >  _decryptor;

    std::unique_ptr<const PackedCryptoBits<pmd>> _v0;
    std::unique_ptr<const PackedCryptoBits<pmd>> _v1;

public:
    explicit PackedBitsEncryptionContext()
        : _parms(seal::scheme_type::bfv)
    {
        _parms.set_poly_modulus_degree(pmd);
        _parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(pmd));
        _parms.set_plain_modulus(seal::PlainModulus::Batching(pmd, 20));

        _context = std::make_unique<seal::SEALContext>(_parms);
        _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
        seal::KeyGenerator keygen(*_context);
        keygen.create_public_key(_public_key);
        keygen.create_relin_keys(_relin_keys);
        _secret_key = keygen.secret_key();
        _encryptor = std::make_unique<seal::Encryptor>(*_context, _public_key);
        _evaluator = std::make_unique<seal::Evaluator>(*_context);
        _decryptor = std::make_unique<seal::Decryptor>(*_context, _secret_key);

        auto qualifiers = _context->first_context_data()->qualifiers();
        // verify if we can use batching
        assert(qualifiers.using_batching);

        _v0 = std::make_unique<const PackedCryptoBits<pmd>>(*this, 0b0);
        _v1 = std::make_unique<const PackedCryptoBits<pmd>>(*this, 0b1);
    }

    inline const seal::Modulus& plain_modulus() const {
        return _parms.plain_modulus();
    }

    inline const seal::BatchEncoder& batch_encoder() const {
        return *_batch_encoder.get();
    }

    inline const seal::Encryptor& encryptor() const {
        return *_encryptor.get();
    }

    inline seal::Decryptor& decryptor() {
        return *_decryptor.get();
    }

    inline const seal::Evaluator& evaluator() const {
        return *_evaluator.get();
    }

    inline const PackedCryptoBits<pmd>& v0() const {
        return *_v0.get();
    }

    inline const PackedCryptoBits<pmd>& v1() const {
        return *_v1.get();
    }

    inline const seal::RelinKeys& relin_keys() const {
        return _relin_keys;
    }
};

template <std::size_t pmd = 4096>
class PackedCryptoBits
{
    // friend class PackedClearBit;
    PackedBitsEncryptionContext<pmd>& _ctxt;
    seal::Ciphertext _encryptedPackedBits;
    
    PackedCryptoBits(PackedBitsEncryptionContext<pmd>& ctxt, 
                     const seal::Ciphertext& packedCipherbits)
        : _ctxt(ctxt), _encryptedPackedBits(packedCipherbits)
    {
    }

public:
    explicit PackedCryptoBits(PackedBitsEncryptionContext<pmd>& ctxt, 
                              std::vector<uint64_t>& bits)
        : _ctxt(ctxt)
    {
        assert(bits.size() <= pmd && "too much elements in the container");
        // if there is not enough coefficients in the bits container
        if (bits.size() < pmd) {
            bits.insert(bits.end(), pmd-bits.size(), 0b0);
        }
        seal::Plaintext plainVector;
        _ctxt.batch_encoder().encode(bits, plainVector);
        _ctxt.encryptor().encrypt(plainVector, _encryptedPackedBits);
    }

    explicit PackedCryptoBits(PackedBitsEncryptionContext<pmd>& ctxt, 
                              uint8_t broadcastedBit)
        : _ctxt(ctxt)
    {
        seal::Plaintext plainVector;
        std::vector<uint64_t> bits(_ctxt.batch_encoder().slot_count(), 
                                   broadcastedBit & 0b1);
        _ctxt.batch_encoder().encode(bits, plainVector);
        _ctxt.encryptor().encrypt(plainVector, _encryptedPackedBits);
    }

    PackedCryptoBits(PackedCryptoBits const& ref)
        : _ctxt(ref._ctxt), _encryptedPackedBits(ref._encryptedPackedBits)
    {
    }

    PackedCryptoBits(PackedCryptoBits&& cbits)
        : _ctxt(cbits._ctxt)
    {
        std::swap(_encryptedPackedBits, cbits._encryptedPackedBits);
    }

    PackedCryptoBits& operator=(const PackedCryptoBits& cbits)
    {
        assert(std::addressof(_ctxt) == std::addressof(cbits._ctxt));
        _encryptedPackedBits = cbits._encryptedPackedBits;
        return *this;
    }

    PackedCryptoBits& operator=(PackedCryptoBits&& cbits)
    {
        std::swap(_ctxt, cbits._ctxt);
        std::swap(_encryptedPackedBits, cbits._encryptedPackedBits);
        return *this;
    }

    // Simultaneous AND operation applied on packed bits
    // [ 0, 0, 1, 1 ] * [ 0, 1, 0, 1 ] = [ 0, 0, 0, 1 ]
    inline PackedCryptoBits and_op(const PackedCryptoBits& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator().multiply(_encryptedPackedBits, rhs._encryptedPackedBits, res);
        _ctxt.evaluator().relinearize_inplace(res, _ctxt.relin_keys());
        return PackedCryptoBits(_ctxt, res);
    }

    /*
    inline PackedCryptoBit and_op_on_clear(const ClearBit& rhs) const {
        seal::Ciphertext res;
        if (rhs.is_zero())
            // equivalent to a multiplication by "0" plaintext
            // NOTE: we can't call multiply_plain with a "0" plaintext because it will result in a transparent cipher
            _ctxt.evaluator()->multiply(_encryptedBit, _ctxt.c0()._encryptedBit, res);
        else
            _ctxt.evaluator()->multiply_plain(_encryptedBit, rhs._encodedBit, res);
        if (_relin)
            _ctxt.evaluator()->relinearize_inplace(res, _ctxt.relin_keys());
        return CryptoBit(_ctxt, res);
    }*/

    // Simultaneous OR operation applied on packed bits
    // [ 0, 0, 1, 1 ] | [ 0, 1, 0, 1 ] = [ 0, 1, 1, 1 ]
    // f(x,y) = x + y - xy
    inline PackedCryptoBits or_op(PackedCryptoBits const& rhs) const {
        seal::Ciphertext res, mul;
        _ctxt.evaluator().add(_encryptedPackedBits, rhs._encryptedPackedBits, res);
        _ctxt.evaluator().multiply(_encryptedPackedBits, rhs._encryptedPackedBits, mul);
        _ctxt.evaluator().relinearize_inplace(mul, _ctxt.relin_keys());
        _ctxt.evaluator().sub_inplace(res, mul);
        return PackedCryptoBits(_ctxt, res);
    }

    // Simultaneous XOR operation applied on packed bits
    // [ 0, 0, 1, 1 ] + [ 0, 1, 0, 1 ] = [ 0, 1, 1, 0 ]
    // f(x,y) = (x-y)^2
    // As a side note, we can't use the addition modulo 2 as the polynome
    // modulus cannot be set to 2 (when batching).
    inline PackedCryptoBits xor_op(const PackedCryptoBits& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator().sub(_encryptedPackedBits, rhs._encryptedPackedBits, res);
        _ctxt.evaluator().square_inplace(res);
        return PackedCryptoBits(_ctxt, res);
    }

    /*
    inline CryptoBit xor_op_on_clear(const ClearBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator()->add_plain(_encryptedBit, rhs._encodedBit, res);
        return CryptoBit(_ctxt, res);
    }*/

    // Simultaneous NOT (bit flip) operation applied on packed bits
    // [ 0, 1 ] => [ 1, 0 ]
    // f(x) = 1 - x
    inline PackedCryptoBits not_op() const {
        seal::Ciphertext res;
        _ctxt.evaluator().sub(_ctxt.v1()._encryptedPackedBits, _encryptedPackedBits, res);
        return PackedCryptoBits(_ctxt, res);
    }

    // [ x_0, x_1, ..., x_n ] => [ 0, 0, ..., 0 ]
    inline PackedCryptoBits& set_to_0() {
        _ctxt.evaluator().multiply_inplace(_encryptedPackedBits, _ctxt.v0()._encryptedPackedBits);
        _ctxt.evaluator().relinearize_inplace(_encryptedPackedBits, _ctxt.relin_keys());
        return *this;
    }

    // [ x_0, x_1, ..., x_n ] => [ 1, 1, ..., 1 ]
    inline PackedCryptoBits& set_to_1() {
        _ctxt.evaluator().add_inplace(_encryptedPackedBits, not_op()._encryptedPackedBits);
        return *this;
    }

    // Simultaneous XNOR operation applied on packed bits
    // [ 0, 0, 1, 1 ] + [ 0, 1, 0, 1 ] = [ 1, 0, 0, 1 ]
    inline PackedCryptoBits xnor_op(const PackedCryptoBits& rhs) const {
        return xor_op(rhs).not_op();
    }

    inline PackedCryptoBits operator&(const PackedCryptoBits& rhs) const {
        return and_op(rhs);
    }

    /*
    inline PackedCryptoBit operator&(const ClearBit& rhs) const {
        return and_op_on_clear(rhs);
    }*/
    
    inline PackedCryptoBits operator|(const PackedCryptoBits& rhs) const {
        return or_op(rhs);
    }

    inline PackedCryptoBits operator^(const PackedCryptoBits& rhs) const {
        return xor_op(rhs);
    }

/*
    inline PackedCryptoBits operator^(const PackedCryptoBits& rhs) const {
        return xor_op_on_clear(rhs);
    }
*/
    inline PackedCryptoBits operator==(const PackedCryptoBits& rhs) const {
        return xnor_op(rhs);
    }

    inline PackedCryptoBits operator!() const { return not_op(); }

    int noise_budget() const {
        return _ctxt.decryptor().invariant_noise_budget(_encryptedPackedBits);
    }

    std::size_t nb_elements() const {
        return _ctxt.batch_encoder().slot_count();
    }

    std::vector<uint64_t> decrypt() {
        seal::Plaintext decryptedPackedBits;
        std::vector<uint64_t> res;
        _ctxt.decryptor().decrypt(_encryptedPackedBits, decryptedPackedBits);
        _ctxt.batch_encoder().decode(decryptedPackedBits, res);
        return res;
    }

    PackedBitsEncryptionContext<pmd>& encryption_context() { return _ctxt; }

    // This function should be replaced by a bootstrapping procedure as it is 
    // illegal in this form (a decryption procedure couldn't be executed by the server).
    void refresh() {
        seal::Plaintext plaintext;
        _ctxt.batch_encoder().encode(decrypt(), plaintext);
        _ctxt.encryptor().encrypt(plaintext, _encryptedPackedBits);
    }
};
/*
template <size_t bitsize>
class ClearBitset;

template <size_t bitsize>
class CryptoBitset
{
    BitEncryptionContext& _ctxt;
    std::vector<CryptoBit> _container;

public:
    using iterator       = std::vector<CryptoBit>::iterator;
    using const_iterator = std::vector<CryptoBit>::const_iterator;

    CryptoBitset(BitEncryptionContext& ctxt, std::vector<CryptoBit>& container)
        : _ctxt(ctxt), _container(container)
    {
        assert(container.size() <= bitsize && "Insufficient bitsize");
        if (container.size() < bitsize)
            // fill the underlying container with extra zeros
            for (size_t i = container.size(); i < bitsize; i++)
                _container.insert(_container.cend(), _ctxt.c0());
    }

public:
    CryptoBitset(BitEncryptionContext& ctxt, std::bitset<bitsize> inputData = std::bitset<bitsize>())
        : _ctxt(ctxt)
    {
        assert(bitsize >= 1);
        assert(bitsize <= inputData.size() && 
               "dataType size will not be enough to store the decrypted value without loss");
        // Little endian encoding (the first digit read is the LSB) i.e.
        // 0101 means 5 in decimal and the four bits are located as follow: 
        // ('1') container[0], ('0') container[1], ('1') container[2] and ('0') container[3]
        for (size_t i = 0; i < bitsize; i++)
            _container.push_back(CryptoBit(_ctxt, inputData[i]));
    }

    CryptoBitset(CryptoBitset const& cbitfield)
        : _ctxt(cbitfield._ctxt), _container(cbitfield._container)
    {
    }

    template<size_t other_bitsize>
    CryptoBitset(CryptoBitset<other_bitsize> const& cbitfield)
        : _ctxt(cbitfield.bit_encryption_context()), _container(cbitfield.underlying_container())
    {
        assert(bitsize >= other_bitsize && 
            "conversion isn't allowed as the dest bitsize isn't enough to store\
             the value without loss");

        // fill the underlying container with extra zeros
        for (size_t i = _container.size(); i < bitsize; i++)
            _container.insert(_container.cend(), _ctxt.c0());
    }

    CryptoBitset(CryptoBitset&& cbitfield)
        : _ctxt(cbitfield._ctxt)
    {
        std::swap(_container, cbitfield._container);
    }

    CryptoBitset& operator=(CryptoBitset&& cbitfield)
    {
        std::swap(_ctxt, cbitfield._ctxt);
        std::swap(_container, cbitfield._container);
        return *this;
    }

    CryptoBitset& operator=(CryptoBitset& cbitfield)
    {
        assert(&_ctxt == &cbitfield._ctxt && 
            "cannot copy an encrypted bitset using different encryption parameters");
        _container = cbitfield._container;
        return *this;
    }

    std::bitset<bitsize> decrypt() {
        std::bitset<bitsize> decryptedValue = 0;
        for (size_t i = 0; i < bitsize; i++)
            decryptedValue[i] = _container[i].decrypt();
        return decryptedValue;
    }

#define AND &
#define XOR ^
#define NOT !

    CryptoBitset select(const CryptoBitset& cond, const CryptoBitset& a, 
                          const CryptoBitset& b) const
    {
        return (cond AND a) XOR ((NOT cond) AND b);
    }

#undef AND
#undef XOR
#undef NOT

    static CryptoBitset broadcast(BitEncryptionContext& ctxt, const CryptoBit& cbit) {
        std::vector<CryptoBit> container(bitsize, cbit);
        return CryptoBitset(ctxt, container);
    }

    // Apply an unary boolean operator on every bit of the CryptoBitset
    CryptoBitset apply_bitwise_unop(std::function<CryptoBit(const CryptoBit&)> op) const
    {
        std::vector<CryptoBit> res;
        for (size_t i = 0; i < bitsize; i++)
            res.push_back(op(_container[i]));
        return CryptoBitset(_ctxt, res);
    }

    // Apply an binary boolean operator between every x_i and y_i of the lhs and rhs
    // Cryptobitsets
    CryptoBitset apply_bitwise_binop(std::function<CryptoBit(const CryptoBit&, 
                                                             const CryptoBit&)> op, 
                                     const CryptoBitset& rhs) const
    {
        std::vector<CryptoBit> res;
        for (size_t i = 0; i < bitsize; i++)
            res.push_back(op(_container[i], rhs[i]));
        return CryptoBitset(_ctxt, res);
    }


    CryptoBitset apply_bitwise_binop_clear(std::function<CryptoBit(const CryptoBit&, 
                                                                   const ClearBit &)> op, 
                                           const ClearBitset<bitsize>& rhs) const
    {
        std::vector<CryptoBit> res;
        for (size_t i = 0; i < bitsize; i++)
            res.push_back(op(_container[i], rhs[i]));
        return CryptoBitset(_ctxt, res);
    }

    // Shifting a bitfield shift times on the left
    // If 0111010 is the internal value, 
    // the 2-shift will be 1101000
    inline CryptoBitset shift_left(size_t shamt) const {
        // a left shift (shift towards the MSB) corresponds to a right shift
        // in our vector encoding
        std::vector<CryptoBit> vec(this->_container);

        for (size_t i = 0; i < std::min(shamt, vec.size()); i++) {
            vec.insert(vec.begin(), _ctxt.c0());
            vec.pop_back();
        }
        return CryptoBitset(_ctxt, vec);
    }

    inline CryptoBitset shift_right(size_t shamt) const {
        // a right shift (towards the LSB) corresponds to a left shift
        // in our vector encoding
        std::vector<CryptoBit> vec(this->_container);

        for (size_t i = 0; i < std::min(shamt, vec.size()); i++) {
            vec.insert(vec.end(), _ctxt.c0());
            vec.erase(vec.begin());
        }
        return CryptoBitset(_ctxt, vec);
    }

    // TODO: use std::rotate
    inline CryptoBitset rotate_left(size_t shamt) const {
        std::vector<CryptoBit> vec(_container);
        // std::rotate(myvector.begin(),myvector.begin()+3,myvector.end());
        for (size_t i = 0; i < shamt; i++) {
            vec.insert(vec.begin(), vec.back());
            vec.pop_back();
        }
        return CryptoBitset(_ctxt, vec);
    }

    inline CryptoBitset rotate_right(size_t shamt) const {
        std::vector<CryptoBit> vec(_container);

        for (size_t i = 0; i < shamt; i++) {
            vec.insert(vec.end(), vec.front());
            vec.erase(vec.begin());
        }
        return CryptoBitset(_ctxt, vec);
    }

    // TODO: remplacer par une logique de move ou pas ?
    template <unsigned nb>
    auto split() const
    {
        std::vector<CryptoBitset<bitsize/nb>> rtn;
        const_iterator it = _container.cbegin();
        const_iterator end = _container.cend();

        while (it != end) {
            std::vector<CryptoBit> v;
            v.reserve(bitsize/nb);
            const auto num_to_copy = std::min(static_cast<long unsigned>(
                std::distance(it, end)), bitsize/nb);
            std::copy(it, it + num_to_copy, std::back_inserter(v));
            rtn.push_back(CryptoBitset<bitsize/nb>(_ctxt, v));
            std::advance(it, num_to_copy);
        }
        return rtn;
    }

    // move logic
    template <unsigned U>
    static CryptoBitset<bitsize> join(BitEncryptionContext& ctxt, 
                                      std::vector<CryptoBitset<U>> bitsetVec) 
    {
        unsigned long int size = std::min(U*bitsetVec.size(), bitsize);

        for (auto& e : bitsetVec) 
            assert(&ctxt == &e.bit_encryption_context());

        std::vector<CryptoBit> newvec;
        newvec.reserve(size);

        size_t index = 0;
        // TODO: voir pour remplacer avec std::copy and std::copyn et move_iterator ? 
        for (typename std::vector<CryptoBitset<U>>::iterator it_cbset = bitsetVec.begin();
            it_cbset != bitsetVec.end() && index < size; it_cbset++)
            for (typename CryptoBitset<U>::iterator it_cbit = it_cbset->begin();
                it_cbit != it_cbset->end() && index < size; it_cbit++, index++)
                newvec.push_back(std::move(*it_cbit));

        // std::copy_n(std::make_move_iterator(vec.begin()), N, arr.begin());
        return CryptoBitset<bitsize>(ctxt, newvec);
    }

    CryptoBitset apply_seq_AND() const
    {
        CryptoBit acc = _container[0];
        for (size_t i = 1; i < bitsize; i++)
            acc = _container[i] & acc;
        return CryptoBitset::broadcast(_ctxt, acc);
    }

    inline CryptoBitset operator&(const CryptoBitset& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::and_op, rhs);
    }

    inline CryptoBitset operator&(const ClearBitset<bitsize>& rhs) const
    {
        return apply_bitwise_binop_clear(&CryptoBit::and_op_on_clear, rhs);
    }

    inline CryptoBitset operator|(const CryptoBitset& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::or_op, rhs);
    }

    inline CryptoBitset operator==(const CryptoBitset& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::xnor_op, rhs);
    }

    inline CryptoBitset operator^(const CryptoBitset& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::xor_op, rhs);
    }

    inline CryptoBitset operator^(const ClearBitset<bitsize>& rhs) const
    {
        return apply_bitwise_binop_clear(&CryptoBit::xor_op_on_clear, rhs);
    }

    inline CryptoBitset operator^=(const ClearBitset<bitsize>& rhs) const
    {
        for (size_t i = 0; i < bitsize; i++)
            _container[i] = _container[i].xor_op_on_clear(rhs[i]);
    }

    inline CryptoBitset operator!() const
    {
        return apply_bitwise_unop(&CryptoBit::not_op);
    }

    inline CryptoBitset operator<<(size_t shamt) const {
        return shift_left(shamt);
    }

    inline CryptoBitset& operator<<=(size_t shamt) 
    {
        for (size_t i = 0; i < std::min(shamt, _container.size()); i++) {
            _container.insert(_container.begin(), _ctxt.c0());
            _container.pop_back();
        }
        return *this;
    }

    inline CryptoBitset operator>>(size_t shamt) const {
        return shift_right(shamt);
    }

    // Return the minimal noise budget of the bitfield, i.e. the noise budget 
    // of the most altered bit
    int min_noise_budget() const {
        int min = _container[0].noise_budget();
        for (size_t i = 1; i < bitsize; i++)
            if (min > _container[i].noise_budget())
                min = _container[i].noise_budget();
       return min;
    }

    inline BitEncryptionContext& bit_encryption_context() const {
        return _ctxt;
    }

    inline std::vector<CryptoBit> underlying_container() const {
        return _container;
    }

    CryptoBit& operator[](size_t i) {
        return _container[i];
    }

    CryptoBit const& operator[](size_t i) const {
        return _container[i];
    }

    void refresh() {
        for (auto& e : _container)
            e.refresh();
    }

    iterator begin() { return _container.begin(); }
    iterator   end() { return _container.end()  ; }

    const_iterator cbegin() const { return _container.cbegin(); }
    const_iterator   cend() const { return _container.cend()  ; }
};

template <typename T, size_t nbElement>
std::bitset<nbElement*8*sizeof(T)> arrayToBitset(std::array<T, nbElement> tab) 
{
    std::bitset<nbElement*8*sizeof(T)> bits;
    bits = tab[nbElement-1];
    for (size_t i = 1; i < nbElement; i++) {
        bits <<= (sizeof(T))*8;
        bits |= tab[nbElement-1 - i];
    }
    return bits;
}

// Warning : It may not works when T are non POD types, because of the use of memcpy()
template <typename T, size_t bitsize>
std::array<T, bitsize/8*sizeof(T)> bitsetToArray(std::bitset<bitsize> bits) 
{
    std::array<T, bitsize/8*sizeof(T)> bitarray;

    size_t i;
    unsigned long long c;
    constexpr unsigned chunk_size = sizeof(unsigned long long);
    std::bitset<bitsize> mask64 = -1ULL;

    for (i = chunk_size; i < bitsize/8*sizeof(T); i+=chunk_size) {
        c = (bits & mask64).to_ullong();
        std::memcpy(&bitarray.data()[i-chunk_size], &c, chunk_size);
        bits >>= 8*chunk_size;
    }
    c = (bits & mask64).to_ullong();
    long unsigned delta = bitsize/8*sizeof(T) - (i - chunk_size);
    std::memcpy(&bitarray.data()[i-chunk_size], &c, delta);

    return bitarray;
}

template <size_t bitsize>
class ClearBitset
{
    std::vector<ClearBit> _container;

public:
    using iterator       = std::vector<ClearBit>::iterator;
    using const_iterator = std::vector<ClearBit>::const_iterator;

public:
    ClearBitset(std::bitset<bitsize> inputData = std::bitset<bitsize>())
    {
        assert(bitsize >= 1);
        assert(bitsize <= inputData.size());
        
        for (size_t i = 0; i < bitsize; i++) {
            _container.push_back(ClearBit(inputData[i]));
            _container[i].decode();
        }
    }

    std::bitset<bitsize> decode() {
        std::bitset<bitsize> decodedValue = 0;
        for (size_t i = 0; i < bitsize; i++)
            decodedValue[i] = _container[i].decode();
        return decodedValue;
    }

    ClearBit& operator[](size_t i) {
        return _container[i];
    }

    ClearBit const& operator[](size_t i) const {
        return _container[i];
    }
};
*/


#endif