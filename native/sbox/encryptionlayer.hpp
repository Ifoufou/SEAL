#ifndef __ENCRYPTION_LAYER_HPP__
#define __ENCRYPTION_LAYER_HPP__

#include <assert.h>
#include <memory>
#include "seal_include.h"

class CryptoBit;

class BitEncryptionContext
{
    seal::EncryptionParameters _parms;
    seal::SecretKey _secret_key;
    seal::PublicKey _public_key;
    seal::RelinKeys _relin_keys;

    std::unique_ptr<seal::Encryptor> _encryptor;
    std::unique_ptr<seal::Evaluator> _evaluator;
    std::unique_ptr<seal::Decryptor> _decryptor;

    std::unique_ptr<const CryptoBit> _c0;
    std::unique_ptr<const CryptoBit> _c1;

public:
    explicit BitEncryptionContext()
        : _parms(seal::scheme_type::bfv)
    {
        _parms.set_poly_modulus_degree(4096);
        _parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(_parms.poly_modulus_degree()));
        // very important
        _parms.set_plain_modulus(2);
        seal::SEALContext context(_parms);
        seal::KeyGenerator keygen(context);
        keygen.create_public_key(_public_key);
        keygen.create_relin_keys(_relin_keys);
        _secret_key = keygen.secret_key();
        _encryptor = std::make_unique<seal::Encryptor>(context, _public_key);
        _evaluator = std::make_unique<seal::Evaluator>(context);
        _decryptor = std::make_unique<seal::Decryptor>(context, _secret_key);
        _c0 = std::make_unique<const CryptoBit>(*this, 0b0);
        _c1 = std::make_unique<const CryptoBit>(*this, 0b1);
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

    inline const seal::Evaluator& evaluator() const {
        return *_evaluator.get();
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

class CryptoBit 
{
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
        _ctxt.evaluator().multiply(_encryptedBit, rhs._encryptedBit, res);
        if (_relin)
            _ctxt.evaluator().relinearize_inplace(res, _ctxt.relin_keys());
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
        _ctxt.evaluator().multiply(_encryptedBit, rhs._encryptedBit, res);
        if (_relin)
            _ctxt.evaluator().relinearize_inplace(res, _ctxt.relin_keys());
        _ctxt.evaluator().add_inplace(res, _encryptedBit);
        _ctxt.evaluator().add_inplace(res, rhs._encryptedBit);
        return CryptoBit(_ctxt, res);
    }

    // XOR operation on encrypted bit
    // 0 ^ 0 = 0
    // 0 ^ 1 = 1
    // 1 ^ 0 = 1
    // 1 ^ 1 = 0
    inline CryptoBit xor_op(const CryptoBit& rhs) const {
        seal::Ciphertext res;
        _ctxt.evaluator().add(_encryptedBit, rhs._encryptedBit, res);
        return CryptoBit(_ctxt, res);
    }

    // NOT (bit flip) operation on encrypted bit
    // 0 + 1 = 1
    // 1 + 1 = 0
    inline CryptoBit not_op() const {
        seal::Ciphertext res;
        _ctxt.evaluator().add(_encryptedBit, _ctxt.c1()._encryptedBit, res);
        return CryptoBit(_ctxt, res);
    }

    inline CryptoBit& set_to_0() {
        _ctxt.evaluator().multiply_inplace(_encryptedBit, _ctxt.c0()._encryptedBit);
        if (_relin)
            _ctxt.evaluator().relinearize_inplace(_encryptedBit, _ctxt.relin_keys());
        return *this;
    }

    inline CryptoBit& set_to_1() {
        _ctxt.evaluator().add_inplace(_encryptedBit, not_op()._encryptedBit);
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
    
    inline CryptoBit operator|(const CryptoBit& rhs) const {
        return or_op(rhs);
    }

    inline CryptoBit operator^(const CryptoBit& rhs) const {
        return xor_op(rhs);
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

    // This function should be replaced by a bootstrapping procedure as it is 
    // illegal in this form (a decryption procedure couldn't be executed by the server).
    void refresh() {
        _ctxt.encryptor().encrypt(uint64_to_hex_string(decrypt() & 0b1), _encryptedBit);
    }
};

template <typename dataType, size_t bitsize>
class CryptoBitField
{
    BitEncryptionContext& _ctxt;
    std::vector<CryptoBit> _container;

    CryptoBitField(BitEncryptionContext& ctxt, std::vector<CryptoBit>& container)
        : _ctxt(ctxt), _container(container)
    {
    }

public:
    using iterator       = std::vector<CryptoBit>::iterator;
    using const_iterator = std::vector<CryptoBit>::const_iterator;

public:
    CryptoBitField(BitEncryptionContext& ctxt, dataType inputData)
        : _ctxt(ctxt)
    {
        assert(bitsize >= 1);
        assert(bitsize <= sizeof(inputData)*8 && 
               "dataType size will not be enough to store the decrypted value without loss");
        // Little endian encoding (the first digit read is the LSB) i.e.
        // 0101 means 5 in decimal and the four bits are located as follow: 
        // ('1') container[0], ('0') container[1], ('1') container[2] and ('0') container[3]
        for (size_t i = 0; i < bitsize; i++)
            _container.push_back(CryptoBit(_ctxt, (inputData >> i) & 0b1));
    }

    CryptoBitField(CryptoBitField const& cbitfield)
        : _ctxt(cbitfield._ctxt), _container(cbitfield._container)
    {
    }

    CryptoBitField& operator=(CryptoBitField&& cbitfield)
    {
        std::swap(_ctxt, cbitfield._ctxt);
        std::swap(_container, cbitfield._container);
        return *this;
    }

    dataType decrypt() {
        dataType decryptedValue = 0;
        for (size_t i = 0; i < bitsize; i++)
            decryptedValue = static_cast<dataType>(_container[i].decrypt() << i) | decryptedValue;
        return decryptedValue;
    }

    static CryptoBitField broadcast(BitEncryptionContext& ctxt, const CryptoBit& cbit) {
        std::vector<CryptoBit> container(bitsize, cbit);
        return CryptoBitField(ctxt, container);
    }

    // Apply an unary boolean operator on every bit of the CryptoBitField
    CryptoBitField apply_bitwise_unop(std::function<CryptoBit(const CryptoBit&)> op) const
    {
        std::vector<CryptoBit> res;
        for (size_t i = 0; i < bitsize; i++)
            res.push_back(op(_container[i]));
        return CryptoBitField(_ctxt, res);
    }

    // Apply an binary boolean operator between every x_i and y_i of the lhs and rhs
    // Cryptobitfields
    CryptoBitField apply_bitwise_binop(std::function<CryptoBit(const CryptoBit&, 
                                                               const CryptoBit&)> op, 
                                       const CryptoBitField& rhs) const
    {
        std::vector<CryptoBit> res;
        for (size_t i = 0; i < bitsize; i++)
            res.push_back(op(_container[i], rhs[i]));
        return CryptoBitField(_ctxt, res);
    }

    CryptoBitField apply_seq_AND() const
    {
        CryptoBit acc = _container[0];
        for (size_t i = 1; i < bitsize; i++)
            acc = _container[i] & acc;
        return CryptoBitField::broadcast(_ctxt, acc);
    }

    inline CryptoBitField operator&(const CryptoBitField& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::and_op, rhs);
    }

    inline CryptoBitField operator|(const CryptoBitField& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::or_op, rhs);
    }

    inline CryptoBitField operator==(const CryptoBitField& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::xnor_op, rhs);
    }

    inline CryptoBitField operator^(const CryptoBitField& rhs) const
    {
        return apply_bitwise_binop(&CryptoBit::xor_op, rhs);
    }

    inline CryptoBitField operator!() const
    {
        return apply_bitwise_unop(&CryptoBit::not_op);
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

#endif