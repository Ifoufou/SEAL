#ifndef __ENCRYPTION_LAYER_HPP__
#define __ENCRYPTION_LAYER_HPP__

#include <assert.h>
#include <bitset>
#include <memory>
#include "seal_include.hpp"

class ClearBit;
class CryptoBit;

class BitEncryptionContext
{
    seal::EncryptionParameters _parms;
    seal::SecretKey _secret_key;
    seal::PublicKey _public_key;
    seal::RelinKeys _relin_keys;

    std::shared_ptr<seal::SEALContext> _context; 
    std::shared_ptr<seal::Encryptor  > _encryptor;
    std::shared_ptr<seal::Evaluator  > _evaluator;
    std::shared_ptr<seal::Decryptor  > _decryptor;

    std::shared_ptr<const CryptoBit> _c0;
    std::shared_ptr<const CryptoBit> _c1;

public:
    explicit BitEncryptionContext(std::size_t poly_modulus_degree = 4096)
        : _parms(seal::scheme_type::bfv)
    {
        _parms.set_poly_modulus_degree(poly_modulus_degree);
        _parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(_parms.poly_modulus_degree()));
        // very important
        _parms.set_plain_modulus(2);
        _context = std::make_shared<seal::SEALContext>(_parms);
        seal::KeyGenerator keygen(*_context);
        keygen.create_public_key(_public_key);
        keygen.create_relin_keys(_relin_keys);
        _secret_key = keygen.secret_key();
        _encryptor = std::make_shared<seal::Encryptor>(*_context, _public_key);
        _evaluator = std::make_shared<seal::Evaluator>(*_context);
        _decryptor = std::make_shared<seal::Decryptor>(*_context, _secret_key);
        _c0 = std::make_shared<const CryptoBit>(*this, 0b0);
        _c1 = std::make_shared<const CryptoBit>(*this, 0b1);
    }

    inline const seal::Modulus& plain_modulus() const {
        return _parms.plain_modulus();
    }

    inline const seal::Encryptor& encryptor() const {
        return *_encryptor.get();
    }

    inline seal::Decryptor& decryptor() {
        return *_decryptor.get();
    }

    inline const std::shared_ptr<seal::Evaluator>& evaluator() const {
        return _evaluator;
    }

    inline const CryptoBit& c0() const {
        return *_c0.get();
    }

    inline const CryptoBit& c1() const {
        return *_c1.get();
    }

    inline const seal::RelinKeys& relin_keys() const {
        return _relin_keys;
    }
};

#define RELIN_ENABLE 1

class ClearBit
{
    friend class CryptoBit;
    seal::Plaintext _encodedBit;
public:
    explicit ClearBit(uint8_t bit)
        : _encodedBit(uint64_to_hex_string(bit & 0b1) == "0" ? 
                      seal::Plaintext(4096, 1) : seal::Plaintext("1"))
    {
    }

    bool is_zero() const {
        return _encodedBit.is_zero();
    }

    uint8_t decode() const {
        return static_cast<uint8_t>(std::stoul(_encodedBit.to_string(), nullptr, 16)) & 0b1;
    }
};

class CryptoBit 
{
    friend class ClearBit;
    BitEncryptionContext& _ctxt;
    seal::Ciphertext _encryptedBit;
    const bool _relin = RELIN_ENABLE;
    
    CryptoBit(BitEncryptionContext& ctxt, const seal::Ciphertext& cipherbit)
        : _ctxt(ctxt), _encryptedBit(cipherbit)
    {
    }

public:
    explicit CryptoBit(BitEncryptionContext& ctxt, uint8_t bit)
        : _ctxt(ctxt)
    {
        if (_ctxt.plain_modulus() != 2)
            assert("plain_modulus must be of value 2!");
        _ctxt.encryptor().encrypt(uint64_to_hex_string(bit & 0b1), _encryptedBit);
    }

    CryptoBit(CryptoBit const& ref)
        : _ctxt(ref._ctxt), _encryptedBit(ref._encryptedBit)
    {
    }

    CryptoBit(CryptoBit&& cbit)
        : _ctxt(cbit._ctxt)
    {
        std::swap(_encryptedBit, cbit._encryptedBit);
    }

    CryptoBit& operator=(const CryptoBit& cbit)
    {
        assert(std::addressof(_ctxt) == std::addressof(cbit._ctxt));
        _encryptedBit = cbit._encryptedBit;
        return *this;
    }

    CryptoBit& operator=(CryptoBit&& cbit)
    {
        std::swap(_ctxt, cbit._ctxt);
        std::swap(_encryptedBit, cbit._encryptedBit);
        return *this;
    }

    // AND operation on encrypted bit
    // Recall that if plain_modulus == 2, the FHE mult. (*) acts as a AND operator
    // 0 * 0 = 0
    // 0 * 1 = 0
    // 1 * 0 = 0
    // 1 * 1 = 1
    inline CryptoBit and_op(const CryptoBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator()->multiply(_encryptedBit, rhs._encryptedBit, res, seal::MemoryPoolHandle::ThreadLocal());
        if (_relin)
            _ctxt.evaluator()->relinearize_inplace(res, _ctxt.relin_keys(), seal::MemoryPoolHandle::ThreadLocal());
        return CryptoBit(_ctxt, res);
    }

    inline CryptoBit and_op_on_clear(const ClearBit& rhs) const {
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
    }

    // OR operation on encrypted bit
    // f(x,y) = x + y + xy mod 2
    // 0 | 0 = 0
    // 0 | 1 = 1
    // 1 | 0 = 1
    // 1 | 1 = 1
    inline CryptoBit or_op(const CryptoBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator()->multiply(_encryptedBit, rhs._encryptedBit, res, seal::MemoryPoolHandle::ThreadLocal());
        if (_relin)
            _ctxt.evaluator()->relinearize_inplace(res, _ctxt.relin_keys(), seal::MemoryPoolHandle::ThreadLocal());
        _ctxt.evaluator()->add_inplace(res, _encryptedBit);
        _ctxt.evaluator()->add_inplace(res, rhs._encryptedBit);
        return CryptoBit(_ctxt, res);
    }

    // XOR operation on encrypted bit
    // 0 + 0 = 0
    // 0 + 1 = 1
    // 1 + 0 = 1
    // 1 + 1 = 0
    inline CryptoBit xor_op(const CryptoBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator()->add(_encryptedBit, rhs._encryptedBit, res);
        return CryptoBit(_ctxt, res);
    }

    inline CryptoBit xor_op_on_clear(const ClearBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator()->add_plain(_encryptedBit, rhs._encodedBit, res);
        return CryptoBit(_ctxt, res);
    }

    // NOT (bit flip) operation on encrypted bit
    // 0 + 1 = 1
    // 1 + 1 = 0
    inline CryptoBit not_op() const {
        seal::Ciphertext res;
        _ctxt.evaluator()->add(_encryptedBit, _ctxt.c1()._encryptedBit, res);
        return CryptoBit(_ctxt, res);
    }

    inline CryptoBit& set_to_0() {
        _ctxt.evaluator()->multiply_inplace(_encryptedBit, _ctxt.c0()._encryptedBit);
        if (_relin)
            _ctxt.evaluator()->relinearize_inplace(_encryptedBit, _ctxt.relin_keys());
        return *this;
    }

    inline CryptoBit& set_to_1() {
        _ctxt.evaluator()->add_inplace(_encryptedBit, not_op()._encryptedBit);
        return *this;
    }

    // XNOR operator
    // 0 + 0 = 1
    // 0 + 1 = 0
    // 1 + 0 = 0
    // 1 + 1 = 1
    inline CryptoBit xnor_op(const CryptoBit& rhs) const {
        return xor_op(rhs).not_op();
    }

    inline CryptoBit operator&(const CryptoBit& rhs) const {
        return and_op(rhs);
    }

    inline CryptoBit operator&(const ClearBit& rhs) const {
        return and_op_on_clear(rhs);
    }
    
    inline CryptoBit operator|(const CryptoBit& rhs) const {
        return or_op(rhs);
    }

    inline CryptoBit operator^(const CryptoBit& rhs) const {
        return xor_op(rhs);
    }

    inline CryptoBit operator^(const ClearBit& rhs) const {
        return xor_op_on_clear(rhs);
    }

    inline CryptoBit operator==(const CryptoBit& rhs) const {
        return xnor_op(rhs);
    }

    inline CryptoBit operator!() const { return not_op(); }

    int noise_budget() const {
        return _ctxt.decryptor().invariant_noise_budget(_encryptedBit);
    }

    uint8_t decrypt() {
        seal::Plaintext decryptedBit;
        _ctxt.decryptor().decrypt(_encryptedBit, decryptedBit);
        return static_cast<uint8_t>(std::stoul(decryptedBit.to_string(), nullptr, 16)) & 0b1;
    }

    BitEncryptionContext& bit_encryption_context() { return _ctxt; }

    // This function should be replaced by a bootstrapping procedure as it is 
    // illegal in this form (a decryption procedure couldn't be executed by the server).
    void refresh() {
        _ctxt.encryptor().encrypt(uint64_to_hex_string(decrypt() & 0b1), _encryptedBit);
    }
};

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

    template <unsigned U>
    static CryptoBitset<bitsize> join(BitEncryptionContext& ctxt, 
                                      std::vector<CryptoBitset<U>>& bitsetVec) 
    {
        unsigned long int size = std::min(U*bitsetVec.size(), bitsize);

        for (auto& e : bitsetVec) 
            assert(&ctxt == &e.bit_encryption_context());

        std::vector<CryptoBit> newvec;
        newvec.reserve(size);

        size_t index = 0;
        for (typename std::vector<CryptoBitset<U>>::iterator it_cbset = bitsetVec.begin();
            it_cbset != bitsetVec.end() && index < size; it_cbset++)
            for (typename CryptoBitset<U>::iterator it_cbit = it_cbset->begin();
                it_cbit != it_cbset->end() && index < size; it_cbit++, index++)
                newvec.push_back(*it_cbit);

        return CryptoBitset<bitsize>(ctxt, newvec);
    }

    // Same as the join() method but with a move semantic
    // Thus, this method is very suitable if the content of the bitsetVec
    // vector could be directly extracted (avoid to use unnecessary copies) 
    template <unsigned U>
    static CryptoBitset<bitsize> move_and_join(BitEncryptionContext& ctxt, 
                                               std::vector<CryptoBitset<U>>& bitsetVec) 
    {
        unsigned long int size = std::min(U*bitsetVec.size(), bitsize);

        for (auto& e : bitsetVec) 
            assert(&ctxt == &e.bit_encryption_context());

        std::vector<CryptoBit> newvec;
        newvec.reserve(size);

        size_t index = 0;
        for (typename std::vector<CryptoBitset<U>>::iterator it_cbset = bitsetVec.begin();
            it_cbset != bitsetVec.end() && index < size; it_cbset++)
            for (typename CryptoBitset<U>::iterator it_cbit = it_cbset->begin();
                it_cbit != it_cbset->end() && index < size; it_cbit++, index++)
                newvec.push_back(std::move(*it_cbit));

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

// -*- Helper functions -*-

// Convert an std::array into an std::bitset
//
// The reason we use intermediates std::array over std::bitset is that the
// C/C++ languages don't allow to use immediates (cst) of size > 64 bits as
// they aren't supported natively by our processors.
//
// For example, it is impossible to specify directly a 128-bit key:
//
//      std::bitset<128> key(0x000102030405060708090A0B0C0D0E0F);
//
// This code won't compile or the compiler will clamp the immediate value
// on its first 64 bits. An alternative solution could be to set the value 
// of the bitset using 2 instructions:
//
//      std::bitset<128> key(08090A0B0C0D0E0F);
//      key |= std::bitset<128>(0x0001020304050607) << 64;
//
// But if we have to handle keys of different size (like with AES), we will 
// have to adapt the shamt (shift amount) value or encapsulate this code into
// a function like for example cstToBitset(uint64_t a, uint64_t b), which can't
// be expanded to something generic (if we want to replace uint64_t with uint8_t
// for example) in a simple manner.
// 
// As we want to expose the least in term of "low-level details" to the programmer 
// and build a generic solution, we chose for this project to use static or 
// automatic array of arbitrary size as an intermediate. Thus, we can specify in a
// unique place all the data and let the helper conversions function do the rest of
// the job:
//
//      std::array<uint8_t, 16> array_key = { 
//          0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 
//          0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
//      };
//
//      // automatic deduction of the template parameters
//      std::bitset<128> bitset_key = arrayToBitset(array_key);
//
template <typename T, size_t nbElement>
std::bitset<nbElement*8*sizeof(T)> arrayToBitset(std::array<T, nbElement>& tab) 
{
    std::bitset<nbElement*8*sizeof(T)> bits;
    bits = tab[nbElement-1];
    for (size_t i = 1; i < nbElement; i++) {
        bits <<= (sizeof(T))*8;
        bits |= tab[nbElement-1 - i];
    }
    return bits;
}

// Convert an std::bitset into an std::array
// NOTE: T must be a raw data type as unsigned char, short, uint8_t...
template <typename T, size_t bitsize>
std::array<T, bitsize/(8*sizeof(T))> bitsetToArray(std::bitset<bitsize> bits) 
{
    std::array<T, bitsize/(8*sizeof(T))> bitarray;

    unsigned long long c = 0ULL;
    constexpr unsigned chunk_size = sizeof(unsigned long long);
    std::bitset<bitsize> mask64 = -1ULL;

    std::size_t i;
    for (i = chunk_size; i < bitsize/(8*sizeof(T)); i+=chunk_size) {
        c = (bits & mask64).to_ullong();
        std::memcpy(&bitarray.data()[i-chunk_size], &c, chunk_size);
        bits >>= 8*chunk_size;
    }
    c = (bits & mask64).to_ullong();
    long unsigned delta = bitsize/(8*sizeof(T)) - (i - chunk_size);
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

    std::bitset<bitsize> decode() const {
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



#endif