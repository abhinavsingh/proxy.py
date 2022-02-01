# Skeleton App

This directory contains a sample standalone application structure which uses `proxy.py`
via `requirements.txt` file.

## Setup

```console
$ git clone https://github.com/abhinavsingh/proxy.py.git
$ cd proxy.py/skeleton
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

## Run It

Start your app and make a web request to `/` and a proxy request via the instance. You will
see log lines like this:

```console
$ python -m app
...[redacted]... - Loaded plugin proxy.http.proxy.HttpProxyPlugin
...[redacted]... - Loaded plugin proxy.http.server.HttpWebServerPlugin
...[redacted]... - Loaded plugin app.plugins.MyWebServerPlugin
...[redacted]... - Loaded plugin app.plugins.MyProxyPlugin
...[redacted]... - Listening on 127.0.0.1:9000
...[redacted]... - Started 16 acceptors in threadless (local) mode
...[redacted]... - HttpProtocolException: HttpRequestRejected b"I'm a tea pot"
...[redacted]... - 127.0.0.1:64601 - GET None:None/get - None None - 0 bytes - 0.64ms
...[redacted]... - 127.0.0.1:64622 - GET / - curl/7.77.0 - 0.95ms
```

Voila!!!

That is your custom app skeleton structure built on top of `proxy.py`.  Now copy the `app` directory
outside of `proxy.py` repo and create your own git repo.  Customize the `app` for your project needs

## Run in detached (backgound) mode

1. For one-off use cases, you can directly use the following command to start the app in background:
   `python -m app 2>&1 &`
2. For production usage, you likely want a process control manager e.g. supervisord, systemd etc
