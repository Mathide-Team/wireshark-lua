# HotRod Protocol Schemas

This directory contains Kaitai Struct schemas for the HotRod protocol.

## Files

- **hotrod40.ksy** - Kaitai Struct schema for HotRod Protocol 4.0
- **hotrod30.ksy** - Kaitai Struct schema for HotRod Protocol 3.0

## What is Kaitai Struct?

[Kaitai Struct](https://kaitai.io/) is a declarative language for describing binary data structures. These schemas provide a formal specification of the HotRod protocol that can be:

- Used to generate parsers in various programming languages
- Serve as documentation for the protocol structure
- Validate protocol implementations
- Generate visualizations of protocol messages

## Usage

### Compile to Parser Code

You can use the Kaitai Struct compiler to generate parser code in various languages:

```bash
# Install Kaitai Struct compiler
# See: https://kaitai.io/#download

# Compile to Python
kaitai-struct-compiler -t python hotrod40.ksy

# Compile to Java
kaitai-struct-compiler -t java hotrod40.ksy

# Compile to C++
kaitai-struct-compiler -t cpp_stl hotrod40.ksy
```

### Visualize Protocol

Use the [Kaitai Struct Web IDE](https://ide.kaitai.io/) to:
1. Load the schema
2. Upload a capture file
3. Visualize the parsed structure

## Protocol Versions

### HotRod 4.0 (hotrod40.ksy)
- Introduced in Infinispan 14.0
- Protocol version byte: 0x28 (40 decimal)
- Key changes: PUT/REPLACE/REMOVE responses include metadata

### HotRod 3.0 (hotrod30.ksy)
- Used in Infinispan 9.x - 13.x
- Protocol version byte: 0x1F (31 decimal)
- Legacy protocol for older Infinispan versions

## Relationship to Wireshark Dissector

The Lua dissector in [src/hotrod.lua](../src/hotrod.lua) implements the same protocol parsing but is optimized for Wireshark. The Kaitai schemas serve as:

- Reference specification
- Cross-validation tool
- Alternative parser implementation
- Documentation

## Links

- [Kaitai Struct](https://kaitai.io/)
- [Kaitai Struct Format Gallery](https://formats.kaitai.io/)
- [HotRod Protocol Specification](https://infinispan.org/docs/stable/titles/hotrod_protocol/hotrod_protocol.html)
