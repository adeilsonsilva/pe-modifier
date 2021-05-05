# PE-Injector

## Install

```
cmake -DCMAKE_BUILD_TYPE=Release \
      -Dpe-parse=dependencies/pe-parse/build/lib/cmake/ \
      -Dpybind11_DIR=~/.local/lib/python3.6/site-packages/pybind11/share/cmake/pybind11/ \
      ..

cmake --build . --target install

# Include pybind module in path to import with python
export PYTHONPATH="$(pwd)":"${PYTHONPATH}"

```

https://github.com/pybind/pybind11/issues/1379
