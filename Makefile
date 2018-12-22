SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v3
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

.PHONY: all clean test package release coverage flake8 build-docker

all: clean test

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	rm -f .coverage
	rm -rf htmlcov

test:
	python tests.py -v

package:
	python setup.py sdist

release:
	python setup.py sdist register upload

coverage: clean
	coverage run tests.py
	coverage html

flake8:
	flake8 --ignore=E501 --builtins="unicode" proxy.py
	flake8 --ignore=E501,W504 tests.py

build-docker:
	docker build -t $(IMAGE_TAG) .
