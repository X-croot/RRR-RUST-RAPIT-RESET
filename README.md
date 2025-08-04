# RRR - Rust Rapid Reset

## 📖 Overview

**RRR (Rust Rapid Reset)** is a high-performance HTTP/2 stream reset tester.

It initiates multiple TLS connections using HTTP/2 and sends a request that is **immediately canceled** using `RST_STREAM`, leveraging the **Rapid Reset** technique to simulate high-load behavior with low bandwidth consumption.

Ideal for testing server robustness under sudden connection drops.

---
![Hacker GIF](https://www.gifcen.com/wp-content/uploads/2022/01/hacker-gif-4.gif)


## ⚙️ Features

| Flag / Option          | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `--target`             | **Required.** Target hostname or IP (no scheme)             |
| `--port`               | Target port (default: `443`)                                |
| `--requests`           | Total number of requests to send (default: `1000`)          |
| `--delay`              | Delay in ms between requests if `--rps` is 0 (default: `0`) |
| `--rps`                | Requests per second. Overrides `--delay` (default: `0`)     |
| `--max-concurrency`    | Number of concurrent async tasks (default: `100`)           |
| `--path`               | Request path (default: `/`)                                 |
| `--randomize-path`     | Append `?id=xxxx` to each request path                      |
| `--random-user-agent`  | Random `User-Agent` header from popular browsers            |
| `--waf-bypass-headers` | Sends a `POST /admin` instead of GET with extra headers     |
| `--burst`              | Send a number of requests in bursts (default: `0`)          |
| `--burst-interval`     | Interval in seconds between bursts (default: `0`)           |

---

## Usage

### 🚀 Run

```bash
cargo run --release -- --target example.com --requests 5000 --random-user-agent
```

---

## Legal Use

This tool is intended for:

* Security researchers with explicit consent
* Penetration testers with client authorization
* Developers in test/staging environments

> ⚠️ **You are solely responsible for how you use this software.**<br>
> The creators and contributors assume no liability for misuse, data loss, downtime, or legal consequences resulting from use of this tool.

---
