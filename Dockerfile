FROM python:3.11-alpine as base

LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
  com.abhinavsingh.description="⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable • \
  😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN • ⏪ Reverse & ⏩ Forward • \
  👮🏿 \"Proxy Server\" framework • 🌐 \"Web Server\" framework • ➵ ➶ ➷ ➠ \"PubSub\" framework • \
  👷 \"Work\" acceptor & executor framework" \
  com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
  com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
  com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py" \
  org.opencontainers.image.source="https://github.com/abhinavsingh/proxy.py"

ENV PYTHONUNBUFFERED 1

ARG SKIP_OPENSSL
ARG PROXYPY_PKG_PATH

COPY README.md /
COPY $PROXYPY_PKG_PATH /

RUN pip install --upgrade pip && \
  pip install \
  --no-index \
  --find-links file:/// \
  proxy.py && \
  rm *.whl && \
  apk add \
  py-cryptography && \
  pip install \
  paramiko==3.4.0

# Use `--build-arg SKIP_OPENSSL=1` to disable openssl installation
RUN if [[ -z "$SKIP_OPENSSL" ]]; then apk update && apk add openssl; fi

EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]
CMD [ \
  "--hostname=0.0.0.0" \
  ]
