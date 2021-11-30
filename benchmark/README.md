# Benchmark

# Table of Contents
- [TL;DR](#tldr)
- [Usage](#usage)
- [Results](#results)

## TL;DR

1 Million requests benchmark results

| Server | Throughput (request/sec) | Num Workers | Running With |
| ------ | ------------ | ------------------------| ------------ |
| `blacksheep` | 46,564 | 10 | uvicorn |
| `proxy.py` | 39,232 | 10 | - |
| `aiohttp` | 6,615 | 1 | - |
| `tornado` | 3,301 | 1 | - |

- On a single core, `proxy.py` yields `~9449 req/sec` throughput.
- Try it using `--num-acceptors=1`

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
```
