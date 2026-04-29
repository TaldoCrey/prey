
# PREY (Packet Routing Engine Yield)

**PREY** is a high-performance, asynchronous networking framework written in Rust.
It is designed to be a robust engine for packet routing, reverse proxies, and user-space security layers.

> This project is in early development stages!

## Vision
To provide a modular and memory-safe infrastructure for:
- Layer 4/7 Reverse Proxying
- High-throughput Load Balancing (Prey-Proxy)
- User-space Firewalls (Prey-Fire)

## Modules
- ### Core
  - The main module of PREY framework, deals with memory management, streams, packets and connections.
- ### Prey-fire
  - A secondary module of PREY framework, deals with userspace firewall implementation.
- ### Prey-proxy
  - Also, a secondary module of PREY framework, deals with proxy and reverse proxy implementation.

---

# Core
The main module of PREY, its the foundation of the whole framework.
Deals with buffers' logic and management, network connection handling
packet receiving and interpretation.

### **Modules:**
- Buffer

---

## Buffer Module
Core module that holds all buffer related code. This module defines
what is a buffer to the framework, how they behave and how they
are created.

The buffers in prey are built on a **Buffer Pool**, this minimizes
memory access and allocation: PREY allocates memory one time, and all the
management of the allocated pool is done by itself. The pool is
sectorized in sections of 2048 bytes each, the **buffers**.

Each buffer is actually a pointer to the 2048 bytes of the pool, starting 
by an offset. The pool is a contiguous memory area, so buffers
exists "one next another". They all have starting points at 
2048 multiple. Each individual buffer uses a headroom strategy:
the first 128 buffer's bytes are skipped when writing data normally
in the buffer. It allows a more efficient header adding further
in the framework execution, so the firewall or proxy does not have to
create another buffer to insert some header before the actual data.

---

Created by **Renan Machado Santos**. Built for performance.

[![Crates.io](https://img.shields.io/crates/v/prey.svg)](https://crates.io/crates/prey)
[![Documentation](https://docs.rs/prey/badge.svg)](https://docs.rs/prey)