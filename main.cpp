#include <Injector.hpp>
#include <string>
#include <iostream>
#include <vendor/argh.h>

int main(int argc, char const *argv[])
{
    argh::parser cmdl(argv);

    if (cmdl[{"-h", "--help"}] || argc != 3)
    {
        std::cout
            << "Usage: " << argv[0]
            << " INPUT.exe OUTPUT.exe"
        << std::endl;
        exit(-1);
    }

    pe_injector::Injector my_injector(cmdl[1], cmdl[2]);

    my_injector.run();

    return 0;
}
