SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v$(shell python proxy.py --version)
LATEST_TAG := $(NS)/$(IMAGE_NAME):latest
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

HTTPS_KEY_FILE_PATH := https-key.pem
HTTPS_CERT_FILE_PATH := https-cert.pem

CA_KEY_FILE_PATH := ca-key.pem
CA_CERT_FILE_PATH := ca-cert.pem
CA_SIGNING_KEY_FILE_PATH := ca-signing-key.pem

.PHONY: all clean test package test-release release coverage lint
.PHONY: container run-container release-container https-certificates ca-certificates

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
	autopep8 --recursive --in-place --aggressive proxy.py
	autopep8 --recursive --in-place --aggressive tests.py
	autopep8 --recursive --in-place --aggressive plugin_examples.py
	flake8 --ignore=E501,W504 --builtins="unicode" proxy.py
	flake8 --ignore=E501,W504 tests.py

container:
	docker build -t $(LATEST_TAG) -t $(IMAGE_TAG) .

run-container:
	docker run -it -p 8899:8899 --rm $(LATEST_TAG)

release-container:
	docker push $(IMAGE_TAG)

https-certificates:
    # Generate server key
	openssl genrsa -out $(HTTPS_KEY_FILE_PATH) 2048
	# Generate server certificate
	openssl req -new -x509 -days 3650 -key $(HTTPS_KEY_FILE_PATH) -out $(HTTPS_CERT_FILE_PATH)

ca-certificates:
	# Generate CA key
	openssl genrsa -out $(CA_KEY_FILE_PATH) 2048
	# Generate CA certificate
	openssl req -new -x509 -days 3650 -key $(CA_KEY_FILE_PATH) -out $(CA_CERT_FILE_PATH)
	# Generate key that will be used to generate domain certificates on the fly
	# Generated certificates are then signed with CA certificate / key generated above
	openssl genrsa -out $(CA_SIGNING_KEY_FILE_PATH) 2048
