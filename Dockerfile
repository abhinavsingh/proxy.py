FROM ghcr.io/abhinavsingh/proxy.py:base as builder

LABEL org.opencontainers.image.title="proxy.py" \
  org.opencontainers.image.description="💫 Ngrok FRP Alternative • ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable • \
  😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN • ⏪ Reverse & ⏩ Forward • \
  👮🏿 \"Proxy Server\" framework • 🌐 \"Web Server\" framework • ➵ ➶ ➷ ➠ \"PubSub\" framework • \
  👷 \"Work\" acceptor & executor framework" \
  org.opencontainers.image.url="https://github.com/abhinavsingh/proxy.py" \
  org.opencontainers.image.source="https://github.com/abhinavsingh/proxy.py" \
  org.opencontainers.image.licenses="BSD-3-Clause" \
  org.opencontainers.image.authors="Abhinav Singh <mailsforabhinav@gmail.com>" \
  org.opencontainers.image.vendor="Abhinav Singh" \
  org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  org.opencontainers.image.documentation="https://github.com/abhinavsingh/proxy.py#readme" \
  org.opencontainers.image.ref.name="abhinavsingh/proxy.py" \
  com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

ARG SKIP_OPENSSL
ARG PROXYPY_PKG_PATH

COPY README.md /
COPY $PROXYPY_PKG_PATH /

# proxy.py itself needs no external dependencies
# Optionally, include openssl to allow
# users to use TLS interception features using Docker
# Use `--build-arg SKIP_OPENSSL=1` to disable openssl installation
RUN /proxy/venv/bin/pip install --no-compile --no-cache-dir \
  -U pip && \
  /proxy/venv/bin/pip install --no-compile --no-cache-dir \
  --no-index \
  --find-links file:/// \
  proxy.py && \
  rm *.whl && \
  find . -type d -name '__pycache__' | xargs rm -rf && \
  rm -rf /var/cache/apk/* && \
  rm -rf /root/.cache/ && \
  /proxy/venv/bin/pip uninstall -y wheel setuptools pip && \
  /usr/local/bin/pip uninstall -y wheel setuptools pip

FROM python:3.12-alpine
COPY --from=builder /README.md /README.md
COPY --from=builder /proxy /proxy
RUN if [[ -z "$SKIP_OPENSSL" ]]; then \
  apk update && \
  apk --no-cache add openssl && \
  rm -rf /var/cache/apk/* && \
  rm -rf /root/.cache/; \
  fi
ENV PATH="/proxy/venv/bin:${PATH}"
EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]
CMD [ \
  "--hostname=0.0.0.0" \
  ]
