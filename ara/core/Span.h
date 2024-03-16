#ifndef SPAN_H
#define SPAN_H

#include <span>

namespace ara
{
    namespace core
    {
        template <typename T>
        using Span = std::span<T>;
    }
}

#endif
