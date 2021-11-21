SHELL := /bin/bash

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
LATEST_TAG := $(NS)/$(IMAGE_NAME):latest
IMAGE_TAG := $(NS)/$(IMAGE_NAME):$(shell ./write-scm-version.sh)

HTTPS_KEY_FILE_PATH := https-key.pem
HTTPS_CERT_FILE_PATH := https-cert.pem
HTTPS_CSR_FILE_PATH := https-csr.pem
HTTPS_SIGNED_CERT_FILE_PATH := https-signed-cert.pem

CA_KEY_FILE_PATH := ca-key.pem
CA_CERT_FILE_PATH := ca-cert.pem
CA_SIGNING_KEY_FILE_PATH := ca-signing-key.pem

OPEN=$(shell which open)
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
OPEN=$(shell which xdg-open)
endif

.PHONY: all https-certificates sign-https-certificates ca-certificates
.PHONY: lib-check lib-clean lib-test lib-package lib-coverage lib-lint lib-pytest
.PHONY: lib-release-test lib-release lib-profile lib-doc
.PHONY: lib-dep lib-flake8 lib-mypy
.PHONY: container container-run container-release
.PHONY: devtools dashboard dashboard-clean

all: lib-test

https-certificates:
	# Generate server key
	python -m proxy.common.pki gen_private_key \
		--private-key-path $(HTTPS_KEY_FILE_PATH)
	python -m proxy.common.pki remove_passphrase \
		--private-key-path $(HTTPS_KEY_FILE_PATH)
	# Generate server certificate
	python -m proxy.common.pki gen_public_key \
		--private-key-path $(HTTPS_KEY_FILE_PATH) \
		--public-key-path $(HTTPS_CERT_FILE_PATH)

sign-https-certificates:
	# Generate CSR request
	python -m proxy.common.pki gen_csr \
		--csr-path $(HTTPS_CSR_FILE_PATH) \
		--private-key-path $(HTTPS_KEY_FILE_PATH) \
		--public-key-path $(HTTPS_CERT_FILE_PATH)
	# Sign CSR with CA
	python -m proxy.common.pki sign_csr \
		--csr-path $(HTTPS_CSR_FILE_PATH) \
		--crt-path $(HTTPS_SIGNED_CERT_FILE_PATH) \
		--hostname example.com \
		--private-key-path $(CA_KEY_FILE_PATH) \
		--public-key-path $(CA_CERT_FILE_PATH)

ca-certificates:
	# Generate CA key
	python -m proxy.common.pki gen_private_key \
		--private-key-path $(CA_KEY_FILE_PATH)
	python -m proxy.common.pki remove_passphrase \
		--private-key-path $(CA_KEY_FILE_PATH)
	# Generate CA certificate
	python -m proxy.common.pki gen_public_key \
		--private-key-path $(CA_KEY_FILE_PATH) \
		--public-key-path $(CA_CERT_FILE_PATH)
	# Generate key that will be used to generate domain certificates on the fly
	# Generated certificates are then signed with CA certificate / key generated above
	python -m proxy.common.pki gen_private_key \
		--private-key-path $(CA_SIGNING_KEY_FILE_PATH)
	python -m proxy.common.pki remove_passphrase \
		--private-key-path $(CA_SIGNING_KEY_FILE_PATH)

lib-check:
	python check.py

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

lib-dep:
	pip install --upgrade pip && \
	pip install \
		-r requirements.txt \
		-r requirements-testing.txt \
		-r requirements-release.txt \
		-r requirements-tunnel.txt && \
	pip install "setuptools>=42"

lib-lint:
	python -m tox -e lint

lib-flake8:
	tox -e lint -- flake8 --all-files

lib-mypy:
	tox -e lint -- mypy --all-files

lib-pytest:
	python -m tox -e python -- -v

lib-test: lib-clean lib-check lib-lint lib-pytest

lib-package: lib-clean lib-check
	python -m tox -e cleanup-dists,build-dists,metadata-validation

lib-release-test: lib-package
	twine upload --verbose --repository-url https://test.pypi.org/legacy/ dist/*

lib-release: lib-package
	twine upload dist/*

lib-doc:
	python -m tox -e lint && \
	$(OPEN) .tox/build-docs/docs_out/index.html

lib-coverage:
	pytest --cov=proxy --cov=tests --cov-report=html tests/ && \
	$(OPEN) htmlcov/index.html

lib-profile:
	sudo py-spy record \
		-o profile.svg \
		-t -F -s -- \
		python -m proxy \
			--num-acceptors 1 \
			--num-workers 1 \
			--disable-http-proxy \
			--enable-web-server \
			--plugin proxy.plugin.WebServerPlugin \
			--log-file /dev/null

devtools:
	pushd dashboard && npm run devtools && popd

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
