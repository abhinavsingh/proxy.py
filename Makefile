SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v$(shell python proxy.py --version)
LATEST_TAG := $(NS)/$(IMAGE_NAME):latest
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

.PHONY: all clean test package test-release release coverage lint container run-container release-container

all: clean test

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	rm -f .coverage
	rm -rf htmlcov
	rm -rf dist

test:
	python -m unittest tests

package: clean
	python setup.py sdist bdist_wheel

test-release: package
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

release: package
	twine upload dist/*

coverage:
	coverage3 run tests.py
	coverage3 html
	open htmlcov/index.html

lint:
	flake8 --ignore=E501,W504 --builtins="unicode" proxy.py
	flake8 --ignore=E501,W504 tests.py
	autopep8 --recursive --in-place --aggressive --aggressive proxy.py
	autopep8 --recursive --in-place --aggressive --aggressive tests.py

container:
	docker build -t $(LATEST_TAG) -t $(IMAGE_TAG) .

run-container:
	docker run -it -p 8899:8899 --rm $(LATEST_TAG)

release-container:
	docker push $(IMAGE_TAG)
