SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
VERSION ?= v$(shell python -m proxy --version)
LATEST_TAG := $(NS)/$(IMAGE_NAME):latest
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(VERSION)

HTTPS_KEY_FILE_PATH := https-key.pem
HTTPS_CERT_FILE_PATH := https-cert.pem

CA_KEY_FILE_PATH := ca-key.pem
CA_CERT_FILE_PATH := ca-cert.pem
CA_SIGNING_KEY_FILE_PATH := ca-signing-key.pem

.PHONY: all https-certificates ca-certificates autopep8 devtools
.PHONY: lib-clean lib-test lib-package lib-release-test lib-release lib-coverage lib-lint lib-profile
.PHONY: container container-run container-release
.PHONY: dashboard dashboard-clean

all: lib-clean lib-test

devtools:
	pushd dashboard && npm run devtools && popd

autopep8:
	autopep8 --recursive --in-place --aggressive proxy
	autopep8 --recursive --in-place --aggressive tests
	autopep8 --recursive --in-place --aggressive setup.py

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

lib-clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	rm -f .coverage
	rm -rf htmlcov
	rm -rf dist
	rm -rf build
	rm -rf proxy.py.egg-info
	rm -rf .pytest_cache
	rm -rf .hypothesis

lib-lint:
	flake8 --ignore=W504 --max-line-length=127 proxy/ tests/ setup.py
	mypy --strict --ignore-missing-imports proxy/ tests/ setup.py

lib-test: lib-lint
	pytest -v tests/

lib-package: lib-clean
	python setup.py sdist

lib-release-test: lib-package
	twine upload --verbose --repository-url https://test.pypi.org/legacy/ dist/*

lib-release: lib-package
	twine upload dist/*

lib-coverage:
	pytest --cov=proxy --cov-report=html tests/
	open htmlcov/index.html

lib-profile:
	sudo py-spy -F -f profile.svg -d 3600 proxy.py

dashboard:
	pushd dashboard && npm run build && popd

dashboard-clean:
	if [[ -d dashboard/public ]]; then rm -rf dashboard/public; fi

container:
	docker build -t $(LATEST_TAG) -t $(IMAGE_TAG) .

container-release:
	docker push $(IMAGE_TAG)
	docker push $(LATEST_TAG)

container-run:
	docker run -it -p 8899:8899 --rm $(LATEST_TAG)
