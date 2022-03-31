#ifndef __LUT_HPP__
#define __LUT_HPP__

template <typename dataType>
class LUTOutput;
template <typename dataType>
class LUTInput;

template <typename dataType>
class LUTEntry
{
    dataType _input ;
    dataType _output;
public:
    LUTEntry(const LUTInput<dataType>& invalue, const LUTOutput<dataType>& outvalue);

    // allow copy between LUTEntry<int> and LUTEntry<uint32_t> for example
    template <typename U>
    LUTEntry(const LUTEntry<U>& entry)
        :  _input (static_cast<dataType>(entry.getInput ())),
           _output(static_cast<dataType>(entry.getOutput()))
    {
    }

    dataType getInput()  const { return  _input; }
    dataType getOutput() const { return _output; }
};

template <typename dataType>
LUTEntry<dataType>::LUTEntry(const LUTInput<dataType>& invalue, const LUTOutput<dataType>& outvalue)
    : _input(invalue._value), _output(outvalue._value)
{
}

template <typename dataType>
class LUTEntry;

template <typename dataType>
class LUTInput
{
    friend LUTEntry<dataType>;
    dataType _value;
public:
    LUTInput(dataType input_data)
        : _value(input_data)
    {
    }

    LUTEntry<dataType> operator->*(const LUTOutput<dataType>& o) {
        return LUTEntry<dataType>(*this, o);
    }
};

template <typename dataType>
class LUTOutput
{
    friend LUTEntry<dataType>;
    dataType _value;
public:
    LUTOutput(dataType outputvalue)
        : _value(outputvalue)
    {
    }
};

#endif