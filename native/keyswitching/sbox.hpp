#ifndef __SBOX_HPP__
#define __SBOX_HPP__

#include <future>
#include <iostream>
#include "encryptionlayer.hpp"
#include "lut.hpp"

template <typename dataType, size_t bitsize>
class S_Box
{
    enum class S_BoxType { by_value, by_functions } _type;
    std::function<CryptoBitset<bitsize>
                  (const CryptoBitset<bitsize>&)> _operations;
        std::function<CryptoBitset<bitsize>
                  (const CryptoBitset<bitsize>&)> _operations_reverse;
    std::vector<LUTEntry<dataType>> _entries;
public:
    template<typename... T>
    S_Box(const LUTEntry<dataType>& first, const T&... s) 
        : _type(S_BoxType::by_value), _entries{s... }
    {
        // the ctor requires at least one map for the LUT
        _entries.insert(_entries.begin(), first);
    }

    S_Box(std::function<CryptoBitset<bitsize>
                       (const CryptoBitset<bitsize>&)> operations,
          std::function<CryptoBitset<bitsize>
                       (const CryptoBitset<bitsize>&)> operations_reverse)
        : _type(S_BoxType::by_functions), _operations(operations), 
          _operations_reverse(operations_reverse)
    {
    }

#define AND   &
#define XNOR ==
#define XOR   ^

    // Return an output value given the input and the LUT maps
    CryptoBitset<bitsize>
    apply(BitEncryptionContext& ctxt, const CryptoBitset<bitsize>& input) const
    {
        if (_type == S_BoxType::by_value) {
            CryptoBitset<bitsize> lutin (ctxt, _entries[0].getInput() );
            CryptoBitset<bitsize> lutout(ctxt, _entries[0].getOutput());
            CryptoBitset<bitsize> output((lutin XNOR input).apply_seq_AND() AND lutout);

            for (size_t i = 1; i < _entries.size(); i++) {
                lutin  = CryptoBitset<bitsize>(ctxt, _entries[i].getInput() );
                lutout = CryptoBitset<bitsize>(ctxt, _entries[i].getOutput());
                output = ((lutin XNOR input).apply_seq_AND() AND lutout) XOR output;
            }
            return output;
        }
        else {
            return _operations(input);
        }
    }

    CryptoBitset<bitsize>
    reverse(BitEncryptionContext& ctxt, const CryptoBitset<bitsize>& input) const
    {
        if (_type == S_BoxType::by_value) {
            CryptoBitset<bitsize> lutout(ctxt, _entries[0].getInput() );
            CryptoBitset<bitsize> lutin (ctxt, _entries[0].getOutput());
            CryptoBitset<bitsize> output((lutin XNOR input).apply_seq_AND() AND lutout);

            for (size_t i = 1; i < _entries.size(); i++) {
                lutout = CryptoBitset<bitsize>(ctxt, _entries[i].getInput() );
                lutin  = CryptoBitset<bitsize>(ctxt, _entries[i].getOutput());
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

extern std::function<CryptoBitset<8>
              (const CryptoBitset<8>&)>
    AES128_SBox_Forward;

extern std::function<CryptoBitset<8>
              (const CryptoBitset<8>&)>
    AES128_SBox_Forward_Parallel;

extern std::function<CryptoBitset<8>
              (const CryptoBitset<8>&)>
    AES128_SBox_Reverse;

extern S_Box<uint8_t, 8> Sbox_AES128; 

template<class None = void>
void ExecInParallel()
{
    return;
}

template<class... Args>
void ExecInParallel(std::function<CryptoBit(CryptoBit const&, CryptoBit const&)>& foo,
                    std::future<CryptoBit>& fp,
                    CryptoBit const a,
                    CryptoBit const b,
                    Args&... args)
{
    fp = std::async(std::launch::async, foo, a, b);
    ExecInParallel(args...);
    fp.wait();
}

template<class... Args>
void ExecInParallel(std::function<CryptoBitset<8>(CryptoBitset<8> const&)>& foo,
                    std::future<CryptoBitset<8>>& fp,
                    CryptoBitset<8> const a,
                    Args&... args)
{
    fp = std::async(foo, a);
    ExecInParallel(args...);
    fp.wait();
}

#endif