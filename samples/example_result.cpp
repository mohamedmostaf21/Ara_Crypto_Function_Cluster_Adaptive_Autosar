#include<iostream>
#include "../ara/core/result.h"


ara::core::Result<int, std::string> divide(int a, int b)
{
    if (b == 0)
    {
        return ara::core::Result<int, std::string>::FromError("Division by zero");
    }
    else
    {
        return ara::core::Result<int, std::string>::FromValue(a / b);
    }
}

int main()
{
    ara::core::Result<int, std::string> result = divide(10, 0);

    if (result.HasValue())
    {
        std::cout << "Result: " << result.Value() << std::endl;
    }
    else
    {
        std::cout << "Error: " << result.Error() << std::endl;
    }

    return 0;
}
