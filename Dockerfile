FROM python:3.7-alpine as base
FROM base as builder

COPY requirements.txt /app/
COPY setup.py /app/
COPY README.md /app/
COPY proxy/ /app/proxy/
WORKDIR /app
RUN pip install --upgrade pip && \
    pip install --install-option="--prefix=/deps" .

FROM base

LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
      com.abhinavsingh.description="⚡⚡⚡Fast, Lightweight, Programmable, TLS interception capable proxy server for Application debugging, testing and development" \
      com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

COPY --from=builder /deps /usr/local

EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]
CMD [ "--hostname=0.0.0.0", \
      "--port=8899" ]
