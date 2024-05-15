FROM ghcr.io/abhinavsingh/proxy.py:base as base

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

# proxy.py itself needs no external dependencies
RUN python -m venv /proxy/venv && \
  /proxy/venv/bin/pip install \
  -U pip && \
  /proxy/venv/bin/pip install \
  --no-index \
  --find-links file:/// \
  proxy.py && \
  rm *.whl

FROM base as builder
COPY --from=builder /proxy /proxy

# Optionally, include openssl to allow
# users to use TLS interception features using Docker
# Use `--build-arg SKIP_OPENSSL=1` to disable openssl installation
RUN if [[ -z "$SKIP_OPENSSL" ]]; then apk update && apk add openssl; fi

ENV PATH="/proxy/.venv/bin:${PATH}"

EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]
CMD [ \
  "--hostname=0.0.0.0" \
  ]
