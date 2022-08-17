pip3 install --upgrade pip
pip3 install .
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done