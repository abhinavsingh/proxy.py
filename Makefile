SHELL := /bin/bash
PYTHON ?= python

NS ?= abhinavsingh
IMAGE_NAME ?= proxy.py
# Override to target specific versions of proxy.py
PROXYPY_CONTAINER_VERSION := latest
# Used by container build and run targets
PROXYPY_CONTAINER_TAG := $(NS)/$(IMAGE_NAME):$(PROXYPY_CONTAINER_VERSION)

CERT_DIR :=

HTTPS_KEY_FILE_PATH := $(CERT_DIR)https-key.pem
HTTPS_CERT_FILE_PATH := $(CERT_DIR)https-cert.pem
HTTPS_CSR_FILE_PATH := $(CERT_DIR)https-csr.pem
HTTPS_SIGNED_CERT_FILE_PATH := $(CERT_DIR)https-signed-cert.pem

CA_CERT_SUFFIX :=
CA_KEY_FILE_PATH := $(CERT_DIR)ca-key$(CA_CERT_SUFFIX).pem
CA_CERT_FILE_PATH := $(CERT_DIR)ca-cert$(CA_CERT_SUFFIX).pem
CA_SIGNING_KEY_FILE_PATH := $(CERT_DIR)ca-signing-key$(CA_CERT_SUFFIX).pem

# Dummy invalid hardcoded value
PROXYPY_PKG_PATH := dist/proxy.py.whl
BUILDX_TARGET_PLATFORM := linux/amd64

OPEN=$(shell which open)
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
OPEN=$(shell which xdg-open)
endif

.PHONY: all https-certificates sign-https-certificates ca-certificates
.PHONY: lib-check lib-clean lib-test lib-package lib-coverage lib-lint lib-pytest
.PHONY: lib-release-test lib-release lib-profile lib-doc lib-pre-commit
.PHONY: lib-dep lib-flake8 lib-mypy lib-speedscope container-buildx-all-platforms
.PHONY: container container-run container-release container-build container-buildx
.PHONY: devtools dashboard dashboard-clean container-without-openssl

all: lib-test

https-certificates:
	# Generate server key
	$(PYTHON) -m proxy.common.pki gen_private_key \
		--private-key-path $(HTTPS_KEY_FILE_PATH)
	$(PYTHON) -m proxy.common.pki remove_passphrase \
		--private-key-path $(HTTPS_KEY_FILE_PATH)
	# Generate server certificate
	$(PYTHON) -m proxy.common.pki gen_public_key \
		--private-key-path $(HTTPS_KEY_FILE_PATH) \
		--public-key-path $(HTTPS_CERT_FILE_PATH)

sign-https-certificates:
	# Generate CSR request
	$(PYTHON) -m proxy.common.pki gen_csr \
		--csr-path $(HTTPS_CSR_FILE_PATH) \
		--private-key-path $(HTTPS_KEY_FILE_PATH) \
		--public-key-path $(HTTPS_CERT_FILE_PATH)
	# Sign CSR with CA
	$(PYTHON) -m proxy.common.pki sign_csr \
		--csr-path $(HTTPS_CSR_FILE_PATH) \
		--crt-path $(HTTPS_SIGNED_CERT_FILE_PATH) \
		--hostname localhost \
		--private-key-path $(CA_KEY_FILE_PATH) \
		--public-key-path $(CA_CERT_FILE_PATH)

ca-certificates:
	# Generate CA key
	$(PYTHON) -m proxy.common.pki gen_private_key \
		--private-key-path $(CA_KEY_FILE_PATH)
	$(PYTHON) -m proxy.common.pki remove_passphrase \
		--private-key-path $(CA_KEY_FILE_PATH)
	# Generate CA certificate
	$(PYTHON) -m proxy.common.pki gen_public_key \
		--private-key-path $(CA_KEY_FILE_PATH) \
		--public-key-path $(CA_CERT_FILE_PATH)
	# Generate key that will be used to generate domain certificates on the fly
	# Generated certificates are then signed with CA certificate / key generated above
	$(PYTHON) -m proxy.common.pki gen_private_key \
		--private-key-path $(CA_SIGNING_KEY_FILE_PATH)
	$(PYTHON) -m proxy.common.pki remove_passphrase \
		--private-key-path $(CA_SIGNING_KEY_FILE_PATH)

lib-check:
	$(PYTHON) check.py

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
	# Doc RST files are cached and can cause issues
	# See https://github.com/abhinavsingh/proxy.py/issues/642#issuecomment-1003444578
	rm -f docs/pkg/*.rst

lib-dep:
	pip install --upgrade pip && \
	pip install \
		-r requirements-testing.txt \
		-r requirements-release.txt \
		-r requirements-tunnel.txt && \
	pip install "setuptools>=42"

lib-pre-commit:
	$(PYTHON) -m pre_commit run --hook-stage manual --all-files -v

lib-lint:
	$(PYTHON) -m tox -e lint

lib-flake8:
	tox -e lint -- flake8 --all-files

lib-mypy:
	tox -e lint -- mypy --all-files

lib-pytest:
	$(PYTHON) -m tox -e python -- -v

lib-test: lib-clean lib-check lib-lint lib-pytest

lib-package: lib-clean lib-check
	$(PYTHON) -m tox -e cleanup-dists,build-dists,metadata-validation

lib-release-test: lib-package
	twine upload --verbose --repository-url https://test.pypi.org/legacy/ dist/*

lib-release: lib-package
	twine upload dist/*

lib-doc:
	$(PYTHON) -m tox -e build-docs && \
	$(OPEN) .tox/build-docs/docs_out/index.html || true

lib-coverage: lib-clean
	pytest --cov=proxy --cov=tests --cov-report=html tests/ && \
	$(OPEN) htmlcov/index.html || true

lib-profile:
	ulimit -n 65536 && \
	sudo py-spy record \
		-o profile.svg \
		-t -F -s -- \
		$(PYTHON) -m proxy \
			--hostname 127.0.0.1 \
			--num-acceptors 1 \
			--num-workers 1 \
			--enable-web-server \
			--plugin proxy.plugin.WebServerPlugin \
			--backlog 65536 \
			--open-file-limit 65536 \
			--log-file /dev/null

lib-speedscope:
	ulimit -n 65536 && \
	sudo py-spy record \
		-o profile.speedscope.json \
		-f speedscope \
		-t -F -s -- \
		$(PYTHON) -m proxy \
			--hostname 127.0.0.1 \
			--num-acceptors 1 \
			--num-workers 1 \
			--enable-web-server \
			--plugin proxy.plugin.WebServerPlugin \
			--backlog 65536 \
			--open-file-limit 65536 \
			--log-file /dev/null

lib-pyreverse:
	rm -f proxy.proxy.Proxy.dot pyreverse.png
	pyreverse -ASmy -c proxy.proxy.Proxy proxy
	dot -Tpng proxy.proxy.Proxy.dot > pyreverse.png
	open pyreverse.png

devtools:
	pushd dashboard && npm install && npm run devtools && popd

dashboard:
	pushd dashboard && npm install && npm run build && popd

dashboard-clean:
	if [[ -d dashboard/public ]]; then rm -rf dashboard/public; fi

container: lib-package
	docker build \
		-t $(PROXYPY_CONTAINER_TAG) \
		--build-arg PROXYPY_PKG_PATH=$$(ls dist/*.whl) .

container-without-openssl: lib-package
	docker build \
		-t $(PROXYPY_CONTAINER_TAG) \
		--build-arg SKIP_OPENSSL=1 \
		--build-arg PROXYPY_PKG_PATH=$$(ls dist/*.whl) .

# Usage:
#
# make container-buildx \
#	-e PROXYPY_PKG_PATH=$(ls dist/*.whl) \
#	-e BUILDX_TARGET_PLATFORM=linux/arm64 \
#	-e PROXYPY_CONTAINER_VERSION=latest
container-buildx:
	docker buildx build \
		--load \
		--platform $(BUILDX_TARGET_PLATFORM) \
		-t $(PROXYPY_CONTAINER_TAG) \
		--build-arg PROXYPY_PKG_PATH=$(PROXYPY_PKG_PATH) .

container-buildx-all-platforms:
	docker buildx build \
		--platform linux/386,linux/amd64,linux/arm/v6,linux/arm/v7,linux/arm64/v8,linux/ppc64le,linux/s390x \
		-t $(PROXYPY_CONTAINER_TAG) \
		--build-arg PROXYPY_PKG_PATH=$(PROXYPY_PKG_PATH) .

container-run:
	docker run -it -p 8899:8899 --rm $(PROXYPY_CONTAINER_TAG)
