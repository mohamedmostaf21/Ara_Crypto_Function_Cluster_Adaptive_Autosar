#ifndef SPAN_H
#define SPAN_H

#include <span>
#include <algorithm>
namespace ara
{
    namespace core
    {
        template <typename T>
        using Span = std::span<T>;
    }
}

#endif
