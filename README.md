# x64dbg-mcp-rust

A high-performance Model Context Protocol (MCP) server plugin for the x64dbg debugger, implemented in **Rust**.

## 🚀 Project Overview

This project runs an **MCP server** directly inside the x64dbg debugger process. It enables LLM-based tools such as **Claude** and **Cursor** to interactively inspect, analyze, and control the debugger remotely.

By leveraging **Rust**, this plugin offers significant improvements over existing implementations:

- **Stability:** Rust's memory safety prevents plugin-induced debugger crashes.
- **Performance:** Built on a non-blocking asynchronous architecture (Tokio) for high-concurrency communication.
- **Self-Contained:** Deploys as a single native DLL (`.dp64`/`.dp32`) with zero external runtime dependencies.
- **Modern Protocol:** Utilizes the official `rmcp` SDK to ensure full compatibility with the latest MCP specifications.

---

## 🏗️ Prerequisites

- **Rust:** 1.75+ (edition 2021)
- **x64dbg SDK:** Included in `vendor/x64dbg-pluginsdk`.
- **Clang/LLVM:** Required for `bindgen` to generate C bindings.
- **Visual Studio Build Tools:** Required for linking with MSVC.

---

## 🛠️ Build & Installation

### 1. Build

Navigate to the `x64dbg-mcp-rust` directory and run the following command:

```bash
cd x64dbg-mcp-rust
cargo build --release
```

### 2. Plugin Installation

Copy the compiled DLL to your x64dbg plugins folder and change the extension:

- **Source File:** `target/release/x64dbg_mcp_rust.dll`
- **Destination:** `x64dbg/release/x64/plugins/x64dbg_mcp_rust.dp64`

### 3. Run

Launch x64dbg. The MCP server will initialize automatically. You can verify the status in the x64dbg log window.

---

## ⚙️ CI/CD Pipeline

The project includes a **GitHub Actions** workflow (`.github/workflows/ci.yml`) that automatically:

- **Builds** the plugin on `windows-latest`.
- **Lints** the code using `clippy` and `rustfmt`.
- **Artifacts**: Uploads the compiled `.dll` as a build artifact.
- **Releases**: Automatically creates a GitHub Release when a new tag (e.g., `v1.2.3`) is pushed.

---

## 🔗 Connection Settings (MCP Client)

Register the following SSE endpoint in your AI tool (e.g., Cursor, Claude Desktop):

- **SSE URL:** `http://127.0.0.1:50301/mcp/sse`

---

## 🧩 Available Tools (40+)

### 1. Basic Debugging & Control

- `ExecuteCommand`: Execute any internal x64dbg command.
- `DebugRun` / `DebugPause` / `DebugStop`: Remote execution state control.
- `DebugStepIn` / `DebugStepOver` / `DebugStepOut`: Fine-grained instruction stepping.
- `GetThreads` / `GetModules` / `GetCallStack`: Insight into process state and metadata.

### 2. Memory & Register Analysis

- `ReadMemory` / `WriteMemory`: Direct memory access at specified addresses.
- `GetRegisters` / `SetRegister`: Full control over CPU general-purpose registers.
- `AssembleMem`: Assemble instructions (e.g., `mov eax, 1`) directly into memory.
- `PatternFindMem`: Search memory for byte patterns (e.g., `48 8b 05 ? ? ?`).
- `MemoryIsValidPtr`: Verify if a pointer is valid and readable.

### 3. Pro-Level Analytical Tools (New!)

- **`GetXrefs`**: Enumerate all cross-references (Calls, Jumps, Data) to a specific address.
- **`GetTcpConnections`**: List all active network sockets and their states.
- **`GetHandles`**: Enumerate system handles (Files, Keys, Mutexes) owned by the process.
- **`GetHeaps`**: Analyze dynamic memory allocation and heap segments.
- **`GetWindows`**: Inspect GUI window structures, handles, and class names.
- **`GetPebTeb`**: Retrieve PEB/TEB addresses for process environment analysis.
- **`DisassembleRange`**: Bulk disassembly of instruction blocks.

### 4. Advanced Automation & Scripting

- **`AnalyzeFunction`**: Perform CFG-based function analysis with flow graph and xrefs.
- **`StructDumpMem`**: Parse memory into C-style structures with alignment/padding support.
- **`YaraScanMem`**: Scan process memory using powerful YARA rules (powered by `boreal`).
- **`ExecuteScript`**: Run **Rhai** scripts for complex, high-speed automated workflows within the GUI thread.
- `SetComment` / `SetLabel`: Enrich the database with labels and documentation.

---

## 📂 Project Structure

- `x64dbg-mcp-rust/`: Core Rust source code and plugin build configuration.
- `vendor/`: SDKs and reference implementations (x64dbg 2025.08.19 SDK).
- `README.md`: This unified documentation.

---

## ⚖️ License

This project is licensed under either the Apache License, Version 2.0 or the MIT license at your option.
