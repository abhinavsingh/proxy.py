FROM python:3-alpine
LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
      com.abhinavsingh.description="Lightweight HTTP, HTTPS, WebSockets Proxy Server in a single Python file" \
#      com.abhinavsingh.build-date="" \
      com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
#      com.abhinavsingh.vcs-ref="" \
      com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

COPY proxy.py /app/
EXPOSE 8899/tcp

WORKDIR /app
ENTRYPOINT [ "./proxy.py" ]
CMD [ "--host=0.0.0.0", \
      "--port=8899", \
      "--backlog=100", \
      "--server-recvbuf-size=8192", \
      "--client-recvbuf-size=8192", \
      "--open-file-limit=1024", \
      "--log-level=INFO" ]
