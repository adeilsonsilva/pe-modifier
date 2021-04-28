#include <Injector.hpp>
#include <string>
#include <iostream>

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        std::cout
            << "Usage: " << argv[0]
            << " INPUT.exe OUTPUT.exe"
        << std::endl;
        exit(-1);
    }

    pe_injector::Injector my_injector(argv[1], argv[2]);

    my_injector.run();

    return 0;
}
