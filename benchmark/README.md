# Benchmark

# Table of Contents
- [TL;DR](#tldr)
- [Usage](#usage)
- [Results](#results)
  - [Proxy.py](#proxypy)
  - [Blacksheep](#blacksheep)
  - [AioHttp](#aiohttp)
  - [Tornado](#tornado)
  - [Flask](#flask)

## TL;DR

1 Million requests benchmark results @ 8000 QPS

| Server | Throughput (request/sec) |
| ------ | ------------ |
| `proxy.py` | 30,351 |
| `blacksheep` | 7,358 |
| `aiohttp` | 6,615 |
| `tornado` | 3,301 |
| `Flask` | 830 |

- On a single core, `proxy.py` yields `7829 req/sec` throughput
- Reference: [Add benchmarks comparison for `proxy.py`, `tornado`, `aiohttp`, `flask`](https://github.com/abhinavsingh/proxy.py/pull/827)

## Usage

```console
❯ git clone https://github.com/abhinavsingh/proxy.py.git
❯ cd proxy.py
❯ pip install -r benchmark/requirements.txt
❯ ./benchmark/compare.sh > /tmp/compare.log 2>&1
```

## Results

```console
❯ cat /tmp/compare.log
CONCURRENCY: 100 workers, QPS: 8000 req/sec, TOTAL DURATION: 1m, TIMEOUT: 1 sec
```

### `Proxy.py`

```console
=============================
Benchmarking Proxy.Py
Server (pid:32232) running


Summary:
  Total:	60.0028 secs
  Slowest:	0.0932 secs
  Fastest:	0.0010 secs
  Average:	0.0060 secs
  Requests/sec:	30351.6691

  Total data:	34602515 bytes
  Size/request:	34 bytes

Response time histogram:
  0.001 [1]	|
  0.010 [994328]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.019 [5110]	|
  0.029 [426]	|
  0.038 [105]	|
  0.047 [15]	|
  0.056 [9]	|
  0.066 [0]	|
  0.075 [0]	|
  0.084 [0]	|
  0.093 [6]	|


Latency distribution:
  10% in 0.0018 secs
  25% in 0.0022 secs
  50% in 0.0028 secs
  75% in 0.0037 secs
  90% in 0.0050 secs
  95% in 0.0060 secs
  99% in 0.0088 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0010 secs, 0.0932 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0071 secs
  resp wait:	0.0059 secs, 0.0008 secs, 0.0932 secs
  resp read:	0.0000 secs, 0.0000 secs, 0.0065 secs

Status code distribution:
  [200]	1000000 responses

Server gracefully shutdown
=============================
```

### `Blacksheep`

```console
=============================
Benchmarking Blacksheep
Server (pid:42973) running

Summary:
  Total:	60.0112 secs
  Slowest:	0.0357 secs
  Fastest:	0.0047 secs
  Average:	0.0136 secs
  Requests/sec:	7358.7628

  Total data:	8390552 bytes
  Size/request:	19 bytes

Response time histogram:
  0.005 [1]	|
  0.008 [3]	|
  0.011 [4]	|
  0.014 [310108]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.017 [123192]	|■■■■■■■■■■■■■■■■
  0.020 [6795]	|■
  0.023 [1008]	|
  0.026 [222]	|
  0.029 [180]	|
  0.033 [58]	|
  0.036 [37]	|


Latency distribution:
  10% in 0.0123 secs
  25% in 0.0127 secs
  50% in 0.0133 secs
  75% in 0.0142 secs
  90% in 0.0152 secs
  95% in 0.0158 secs
  99% in 0.0181 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0047 secs, 0.0357 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0006 secs
  resp wait:	0.0136 secs, 0.0030 secs, 0.0356 secs
  resp read:	0.0000 secs, 0.0000 secs, 0.0010 secs

Status code distribution:
  [200]	441608 responses



Server gracefully shutdown
=============================
```

### `AioHttp`

```console
=============================
Benchmarking AIOHTTP
Server (pid:31148) running

Summary:
  Total:	60.0098 secs
  Slowest:	1.4160 secs
  Fastest:	0.0026 secs
  Average:	0.0153 secs
  Requests/sec:	6615.5052

  Total data:	7260812 bytes
  Size/request:	19 bytes

Response time histogram:
  0.003 [1]	|
  0.144 [381427]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.285 [67]	|
  0.427 [133]	|
  0.568 [16]	|
  0.709 [300]	|
  0.851 [100]	|
  0.992 [100]	|
  1.133 [1]	|
  1.275 [0]	|
  1.416 [3]	|


Latency distribution:
  10% in 0.0129 secs
  25% in 0.0133 secs
  50% in 0.0138 secs
  75% in 0.0146 secs
  90% in 0.0155 secs
  95% in 0.0164 secs
  99% in 0.0203 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0026 secs, 1.4160 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0006 secs
  resp wait:	0.0152 secs, 0.0025 secs, 1.4160 secs
  resp read:	0.0000 secs, 0.0000 secs, 0.9854 secs

Status code distribution:
  [200]	382148 responses

Error distribution:
  [96]	Get "http://127.0.0.1:8080/http-route-example": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
  [14751]	Get "http://127.0.0.1:8080/http-route-example": dial tcp 127.0.0.1:8080: connect: connection refused

Server gracefully shutdown
=============================
```

### `Tornado`

```console
=============================
Benchmarking Tornado
Server (pid:31161) running

Summary:
  Total:	60.0208 secs
  Slowest:	0.1234 secs
  Fastest:	0.0050 secs
  Average:	0.0323 secs
  Requests/sec:	3301.1874

  Total data:	3515190 bytes
  Size/request:	19 bytes

Response time histogram:
  0.005 [1]	|
  0.017 [6]	|
  0.029 [13657]	|■■■
  0.040 [168114]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.052 [2458]	|■
  0.064 [411]	|
  0.076 [194]	|
  0.088 [72]	|
  0.100 [6]	|
  0.112 [34]	|
  0.123 [57]	|


Latency distribution:
  10% in 0.0288 secs
  25% in 0.0299 secs
  50% in 0.0317 secs
  75% in 0.0338 secs
  90% in 0.0360 secs
  95% in 0.0378 secs
  99% in 0.0426 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0000 secs, 0.0050 secs, 0.1234 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0005 secs
  resp wait:	0.0322 secs, 0.0048 secs, 0.0960 secs
  resp read:	0.0000 secs, 0.0000 secs, 0.0010 secs

Status code distribution:
  [200]	185010 responses

Error distribution:
  [13130]	Get "http://127.0.0.1:8888/http-route-example": dial tcp 127.0.0.1:8888: connect: connection refused

Server gracefully shutdown
=============================
```

### `Flask`

```console
=============================
Benchmarking Flask
Server (pid:31127) running

Summary:
  Total:	60.3213 secs
  Slowest:	1.0974 secs
  Fastest:	0.0007 secs
  Average:	0.0634 secs
  Requests/sec:	830.1539

  Total data:	637602 bytes
  Size/request:	19 bytes

Response time histogram:
  0.001 [1]	|
  0.110 [32803]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.220 [438]	|■
  0.330 [198]	|
  0.439 [0]	|
  0.549 [1]	|
  0.659 [1]	|
  0.768 [2]	|
  0.878 [1]	|
  0.988 [94]	|
  1.097 [19]	|


Latency distribution:
  10% in 0.0412 secs
  25% in 0.0580 secs
  50% in 0.0637 secs
  75% in 0.0649 secs
  90% in 0.0676 secs
  95% in 0.0716 secs
  99% in 0.1668 secs

Details (average, fastest, slowest):
  DNS+dialup:	0.0010 secs, 0.0007 secs, 1.0974 secs
  DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:	0.0000 secs, 0.0000 secs, 0.0007 secs
  resp wait:	0.0620 secs, 0.0005 secs, 1.0967 secs
  resp read:	0.0003 secs, 0.0000 secs, 0.9407 secs

Status code distribution:
  [200]	33558 responses

Error distribution:
  [3359]	Get "http://127.0.0.1:8000/http-route-example": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
  [12904]	Get "http://127.0.0.1:8000/http-route-example": dial tcp 127.0.0.1:8000: connect: connection refused
  [255]	Get "http://127.0.0.1:8000/http-route-example": dial tcp 127.0.0.1:8000: i/o timeout (Client.Timeout exceeded while awaiting headers)

Server gracefully shutdown
=============================
```
