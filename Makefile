SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v3
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

.PHONY: all clean test package release build-docker

all: clean test

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

test:
	python tests.py -v

package:
	python setup.py sdist

release:
	python setup.py sdist register upload

build-docker:
	docker build -t $(IMAGE_TAG) .

