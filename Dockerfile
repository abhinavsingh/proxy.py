FROM python:3.7-alpine as base
FROM base as builder

COPY requirements.txt .
RUN pip install --upgrade pip && pip install --install-option="--prefix=/deps" -r requirements.txt

FROM base

LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
      com.abhinavsingh.description="⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file" \
      com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

COPY --from=builder /deps /usr/local
COPY proxy.py /app/
WORKDIR /app
EXPOSE 8899/tcp
ENTRYPOINT [ "./proxy.py" ]
CMD [ "--hostname=0.0.0.0", \
      "--port=8899" ]
