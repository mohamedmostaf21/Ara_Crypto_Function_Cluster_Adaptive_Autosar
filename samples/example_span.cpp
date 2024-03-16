#include <iostream>
#include <span>
#include <vector>
#include <array>

void printContent(std::span<int> container)
{
    for (auto element : container)
    {
        std::cout << element << " ";
    }
    std::cout << std::endl;
}

void modifyContent(std::span<int> container)
{
    for (auto& element : container)
    {
        element *= 2;
    }
    std::cout << std::endl;
}

int main()
{
    int arr1[] = { 1, 2, 3, 4 };
    printContent(arr1);

    std::vector<int> arr2 = {1,2,3,4};
    printContent(arr2);
    
    std::array<int,4> arr3 = {1,2,3,4};
    printContent(arr3);

    modifyContent(arr1);
    modifyContent(arr2);
    modifyContent(arr3);

    printContent(arr1);
    printContent(arr2);
    printContent(arr3);

    return 0;
}
