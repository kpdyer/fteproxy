all:
	rm -rf build &>/dev/null
	rm -rf src/*.so &>/dev/null
	rm -rf re2.so &>/dev/null
	rm -rf src/re2.cpp &>/dev/null
	python setup.py --cython build_ext --inplace

test: all
	cp -v re2.so tests
	(cd tests && python re2_test.py)
	(cd tests && python test_re.py)
