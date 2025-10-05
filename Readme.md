# GeoTrace Utilities

This project builds two standalone C++17 network utilities:

| Binary | Purpose |
|---------|----------|
| **`bin/geo_ip`** | Simple HTTP/HTTPS client that queries your public IP using OpenSSL |
| **`bin/geo_trace`** | TCP-based geographical traceroute using raw sockets or connect()-based probing |

Both are for Linux only. please use a linux machine with a NIC available.
For VMs, use bridge or use an external NIC chip like a USB ethernet adapter.

---

## 🧱 Build Instructions

### 1. Requirements

- **C++17** compiler (`g++` ≥ 9 or `clang++` ≥ 10)
- **Make**
- **OpenSSL 3.x**
  - macOS: `brew install openssl@3`
  - Ubuntu/Debian: `sudo apt install libssl-dev`

### 2. Build Commands

```bash
# Build everything (default)
make

# Build only the public-IP client
make ip        # or: make geo_ip / make find_ip

# Build only the TCP tracer
make trace     # or: make geo_trace

# Clean build artifacts
make clean
````

### All compiled binaries will appear in:

```
bin/
  ├── geo_ip
  └── geo_trace
```

---

## ⚙️ Usage

### 1. Public IP Client ( does a TCP - HTTPS request.)

```bash
./bin/geo_ip https://ifconfig.me
./bin/geo_ip http://ip-api.com/json
```

launches a simple HTTP(S) GET request to the specified URL and prints the response body.

---

### 2. Geo Traceroute

Traceroute over TCP to visualize hop-by-hop routing.

Basic example:

```bash
sudo ./bin/geo_trace cloudflare.com 443
```

Extended usage:

```bash
sudo ./bin/geo_trace <host> [port] [max_ttl] [timeout_ms] [--mode=raw|connect] [--log=file]
```

Examples:

```bash
# Use connect() probes with diagnostic logging
sudo ./bin/geo_trace usp.ac.fj 443 30 2000 --mode=connect --log=diag_usp.txt

# Use raw socket probes
sudo ./bin/geo_trace google.com --mode=raw --log=diag_raw.txt
```

---

## 🗂️ Directory Layout

```
.
├── include/           # Headers (net_compat.hpp, icmp_listener.hpp, tcp_socket.hpp, etc.)
├── src/               # Source files
│   ├── tcp_probe.cpp / *_raw.cpp / *_connect.cpp
│   ├── geo_resolver.cpp
│   ├── dns_resolver.cpp
│   └── ...
├── main_ip.cpp        # Entry point for geo_ip
├── main_trace.cpp     # Entry point for geo_trace
├── Makefile
└── bin/               # Output binaries (created after build)
```

---

## 🔍 Troubleshooting

* **Permission denied / missing hops:**
  `geo_trace` uses raw sockets — run with `sudo`.

* **Intermediate hops missing:**
  ICMP `Time Exceeded` packets may be filtered by NAT or firewalls.
  Try `--mode=connect` to use fallback TCP connect probing. 
* Some routes are black holes. do not expect all to return
* If you set the max TTL too fast, you may expire before the ICMP_TIME_EXCEEDED is received.
* Recommended TTL setting for the CLI input is 2000, but you can adjust it to 10000 or more.

---

## 🧾 License

MIT License © 2025
Author: Kim Seung Hyun

---

### Quick Summary

| Task              | Command                              |
| ----------------- | ------------------------------------ |
| Build everything  | `make`                               |
| Build tracer only | `make trace`                         |
| Run tracer        | `sudo ./bin/geo_trace <host> <port>` |
| Build IP client   | `make ip`                            |
| Run IP client     | `./bin/geo_ip <url>`                 |
| Clean all         | `make clean`                         |


