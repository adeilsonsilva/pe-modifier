#include <Injector.hpp>
#include <string>
#include <iostream>
#include <vendor/argh.h>

int main(int argc, char const *argv[])
{
    argh::parser cmdl;

    cmdl.add_params({"-h", "--help", "-i", "--input", "-o", "--output", "-m", "--middleware"});

    cmdl.parse(argc, argv, argh::parser::PREFER_PARAM_FOR_UNREG_OPTION);

    if (cmdl[{"-h", "--help"}] || argc < 3)
    {
        std::cout
            << "Usage: " << argv[0]
            << " -i INPUT.exe -o OUTPUT.exe [-m MIDDLEWARE.exe]"
        << std::endl;
        exit(-1);
    }

    auto input      = cmdl({"-i", "--input"}).str();
    auto output     = cmdl({"-o", "--output"}).str();
    auto middleware = cmdl({"-m", "--middleware"}).str();

    if (!input.empty() && !output.empty())
    {
        if (!middleware.empty())
        {
            std::cout << "USING THREE" << std::endl;
            pe_injector::Injector my_injector(input,
                                              middleware,
                                              output);

            my_injector.run();
        }
        else
        {
            std::cout << "USING TWO" << std::endl;
            pe_injector::Injector my_injector(input,
                                              output);

            my_injector.run();
        }
    }


    return 0;
}
