#include <Injector.hpp>

#include <iostream>

namespace pe_injector {

Injector::Injector(const std::string &input_path,
                   const std::string &output_path)
  : m_input(input_path),
    m_output(output_path)
{

}

void
Injector::run()
{
  std::cout << m_input << " => " << m_output << std::endl;

  Section test(1,2,3,4,5);
}

}; // end namespacepe_injector
