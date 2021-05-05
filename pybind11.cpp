#include <pybind11/pybind11.h> // module definitions
#include <pybind11/stl.h>      // conversion of std types

#include <Section.hpp>

namespace py = pybind11;

using namespace pe_injector;
using namespace std;

// Module name must be the same defined in CMakeLists
PYBIND11_MODULE(pe_injector_py, m) {
    py::class_<Section>(m, "Section")
        .def(py::init<const uint     &,
                      const uint32_t &,
                      const uint32_t &,
                      const uint     &,
                      const uint32_t &,
                      const bool     &>())
        .def(py::init<const vector<uint8_t> &,
                      const uint32_t &,
                      const uint32_t &,
                      const uint     &,
                      const uint32_t &>())
        .def("getHeaderSize",
             &Section::getHeaderSize)
        .def("getHeaderData",
             &Section::getHeaderData)
        .def("getData",
             &Section::getData)
        .def("getNextSectionVirtualAddress",
             &Section::getNextSectionVirtualAddress)
        .def_static("align",
                    &Section::align)
        .def("generate_payload",
             &Section::generate_payload)
        .def("gen_padding_bytes",
             &Section::gen_padding_bytes);
}
