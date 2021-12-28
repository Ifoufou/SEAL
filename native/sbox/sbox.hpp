#ifndef __SBOX_HPP__
#define __SBOX_HPP__

#include <iostream>
#include "encryptionlayer.hpp"
#include "LUT.hpp"

template <typename dataType, size_t bitsize>
class S_Box
{
    enum class S_BoxType { by_value, by_functions } _type;
    std::function<CryptoBitField<dataType, bitsize>
                  (const CryptoBitField<dataType, bitsize>&)> _operations;
        std::function<CryptoBitField<dataType, bitsize>
                  (const CryptoBitField<dataType, bitsize>&)> _operations_reverse;
    std::vector<LUTEntry<dataType>> _entries;
public:
    template<typename... T>
    S_Box(const LUTEntry<dataType>& first, const T&... s) 
        : _type(S_BoxType::by_value), _entries{s... }
    {
        // the ctor requires at least one map for the LUT
        _entries.insert(_entries.begin(), first);
    }

    S_Box(std::function<CryptoBitField<dataType, bitsize>
                       (const CryptoBitField<dataType, bitsize>&)> operations,
          std::function<CryptoBitField<dataType, bitsize>
                       (const CryptoBitField<dataType, bitsize>&)> operations_reverse)
        : _type(S_BoxType::by_functions), _operations(operations), 
          _operations_reverse(operations_reverse)
    {
    }

#define AND   &
#define XNOR ==
#define XOR   ^

    // Return an output value given the input and the LUT maps
    CryptoBitField<dataType, bitsize>
    apply(BitEncryptionContext& ctxt, const CryptoBitField<dataType, bitsize>& input) const
    {
        if (_type == S_BoxType::by_value) {
            CryptoBitField<dataType, bitsize> lutin (ctxt, _entries[0].getInput() );
            CryptoBitField<dataType, bitsize> lutout(ctxt, _entries[0].getOutput());
            CryptoBitField<dataType, bitsize> output((lutin XNOR input).apply_seq_AND() AND lutout);

            for (size_t i = 1; i < _entries.size(); i++) {
                lutin  = CryptoBitField<dataType, bitsize>(ctxt, _entries[i].getInput() );
                lutout = CryptoBitField<dataType, bitsize>(ctxt, _entries[i].getOutput());
                output = ((lutin XNOR input).apply_seq_AND() AND lutout) XOR output;
            }
            return output;
        }
        else {
            return _operations(input);
        }
    }

    CryptoBitField<dataType, bitsize>
    reverse(BitEncryptionContext& ctxt, const CryptoBitField<dataType, bitsize>& input) const
    {
        if (_type == S_BoxType::by_value) {
            CryptoBitField<dataType, bitsize> lutout(ctxt, _entries[0].getInput() );
            CryptoBitField<dataType, bitsize> lutin (ctxt, _entries[0].getOutput());
            CryptoBitField<dataType, bitsize> output((lutin XNOR input).apply_seq_AND() AND lutout);

            for (size_t i = 1; i < _entries.size(); i++) {
                lutout = CryptoBitField<dataType, bitsize>(ctxt, _entries[i].getInput() );
                lutin  = CryptoBitField<dataType, bitsize>(ctxt, _entries[i].getOutput());
                output = ((lutin XNOR input).apply_seq_AND() AND lutout) XOR output;
            }
            return output;
        }
        else {
            return _operations_reverse(input);
        }
    }

#undef AND
#undef XNOR
#undef XOR

};

#endif