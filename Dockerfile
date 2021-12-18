FROM python:3.10-alpine as base
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
ARG PROXYPY_PKG_PATH

COPY README.md /
COPY $PROXYPY_PKG_PATH /
RUN pip install --upgrade pip && \
  pip install \
  --no-index \
  --find-links file:/// \
  proxy.py && \
  rm *.whl

# Install openssl to enable TLS interception & HTTPS proxy options within container
# NOTE: You can comment out this line if you don't intend to use those features.
RUN apk update && apk add openssl

EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]
CMD [ "--hostname=0.0.0.0 --local-executor" ]
