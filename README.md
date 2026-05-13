# DPI Engine – Python Port

Python 3.8+ conversion of the C++ Deep Packet Inspection engine from
[shashvatsinghcfc-sudo/dupe1](https://github.com/shashvatsinghcfc-sudo/dupe1).

No third-party packages are required – the entire port uses the Python
standard library only.

---

## File Map  (C++ → Python)

| C++ file | Python file | Description |
|---|---|---|
| `include/types.h` + `src/types.cpp` | `dpi_types.py` | Core data structures, enums, helpers |
| `include/pcap_reader.h` + `src/pcap_reader.cpp` | `pcap_reader.py` | PCAP file reader/writer |
| `include/packet_parser.h` + `src/packet_parser.cpp` | `packet_parser.py` | Ethernet/IP/TCP/UDP header parsing |
| `include/sni_extractor.h` + `src/sni_extractor.cpp` | `sni_extractor.py` | TLS SNI + HTTP Host extraction |
| `include/rule_manager.h` | `rule_manager.py` | Thread-safe blocking rules |
| `include/thread_safe_queue.h` | `thread_safe_queue.py` | Bounded thread-safe queue |
| `include/connection_tracker.h` | `connection_tracker.py` | Per-FP flow table |
| `include/fast_path.h` | `fast_path.py` | Fast Path DPI processing thread |
| `include/load_balancer.h` | `load_balancer.py` | Load Balancer distribution thread |
| `src/main_working.cpp` | `main_simple.py` | **Simple single-threaded engine** |
| `src/dpi_mt.cpp` | `dpi_engine.py` | **Multi-threaded engine** |

---

## Usage

### Simple (single-threaded) – mirrors `main_working.cpp`

```bash
python main_simple.py input.pcap output.pcap
python main_simple.py input.pcap output.pcap --block-app YouTube --block-domain tiktok
```

### Multi-threaded – mirrors `dpi_mt.cpp`

```bash
python dpi_engine.py input.pcap output.pcap
python dpi_engine.py input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook \
    --lbs 2 --fps 2
```

### Available flags (both scripts)

| Flag | Example | Effect |
|---|---|---|
| `--block-app APP` | `--block-app YouTube` | Drop all flows classified as that app |
| `--block-ip IP` | `--block-ip 10.0.0.5` | Drop all packets from source IP |
| `--block-domain STR` | `--block-domain tiktok` | Drop flows whose SNI contains the substring |
| `--lbs N` *(mt only)* | `--lbs 4` | Number of Load Balancer threads |
| `--fps N` *(mt only)* | `--fps 4` | Fast Path threads per LB |

---

## Architecture

### Single-threaded packet journey

```
PcapReader → PacketParser → 5-tuple lookup → SNIExtractor
           → RuleManager.is_blocked() → PcapWriter / drop
```

### Multi-threaded pipeline

```
PcapReader
    │  hash(5-tuple) % num_lbs
    ▼
LoadBalancer threads  (TSQueue → FP selection)
    │  hash(5-tuple) % num_fps
    ▼
FastPath threads  (ConnectionTracker + SNI + rules)
    │
    ▼  (output TSQueue)
PcapWriter thread
```

Consistent hashing ensures all packets of the same TCP/UDP flow always
reach the same FastPath thread, so flow state (SNI, app classification,
blocked flag) is maintained correctly without per-flow locking.

---

## Key design decisions

- **`dpi_types.py`** – renamed from `types.py` to avoid shadowing Python's
  built-in `types` module.
- **`TSQueue`** wraps `queue.Queue` (stdlib) which already uses a `Condition`
  internally – exactly matching the C++ `std::mutex` + `std::condition_variable`
  pattern.
- **`FiveTuple`** is a frozen `dataclass`, making it hashable so it can be
  used directly as a `dict` key (replacing C++ `std::unordered_map`).
- **No external dependencies** – `scapy`, `dpkt`, and `pyshark` are
  intentionally avoided to stay as close as possible to the C++ code that
  also uses no external libraries.
