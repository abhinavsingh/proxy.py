SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v0.3
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

.PHONY: all clean test package test-release release coverage flake8 container

all: clean test

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	rm -f .coverage
	rm -rf htmlcov
	rm -rf dist

test:
	python tests.py -v

package: clean
	python setup.py sdist bdist_wheel

test-release: package
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

release: package
	twine upload dist/*

coverage:
	coverage run tests.py
	coverage html

flake8:
	flake8 --ignore=E501,W504 --builtins="unicode" proxy.py
	flake8 --ignore=E501,W504 tests.py

container:
	docker build -t $(IMAGE_TAG) .
