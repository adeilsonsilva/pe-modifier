/**
 * @file PEInjector.hpp
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2021-04-27
 *
 * @copyright Copyright (c) 2021
 *
 */

#pragma once

#ifndef INJECTOR_HPP
#define INJECTOR_HPP

#include <Section.hpp>
#include <parser-library/parse.h>

#include <string>

namespace pe_injector {

class Injector
{

public:
  Injector(const std::string &input_path,
           const std::string &output_path);

  ~Injector() {};

  void run();


private:

    std::string m_input;
    std::string m_output;

};// end Section class
} // end namespace pe_injector

#endif // INJECTOR_HPP
