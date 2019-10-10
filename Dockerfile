FROM python:3-alpine
LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
      com.abhinavsingh.description="⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file" \
      com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

RUN pip install --upgrade pip && pip install typing-extensions==3.7.4

COPY proxy.py /app/
EXPOSE 8899/tcp

WORKDIR /app
ENTRYPOINT [ "./proxy.py" ]
CMD [ "--hostname=0.0.0.0", \
      "--port=8899" ]
