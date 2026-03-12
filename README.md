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

## 🔗 Connection Settings (MCP Client)

Register the following SSE endpoint in your AI tool (e.g., Cursor, Claude Desktop):

- **SSE URL:** `http://127.0.0.1:50301/mcp/sse`

---

## 🧩 Available Tools (MCP Tools)
- `ExecuteCommand`: Execute any internal x64dbg command (e.g., `init`, `run`, `bp`).
- `ReadMemory` / `WriteMemory`: Read from or write to the debuggee's memory at a specific address.
- `EvaluateExpression`: Evaluate mathematical expressions or resolve addresses (e.g. `[esp+8]`, `rax+0x10`).
- `Disassemble`: Get disassembly of instructions starting at a specific address.
- `GetRegisters` / `SetRegister`: Read and write general-purpose registers.
- `GetBreakpoints` / `SetBreakpoint`: List and set software breakpoints.
- `GetThreads`: List all threads in the process.
- `GetModules`: List all loaded modules in the process.
- `GetCallStack`: Get the current call stack for the active thread.
- `SetComment` / `SetLabel`: Set a comment or label at a specific address.

---

## 📂 Project Structure
- `x64dbg-mcp-rust/`: Core Rust source code and build configuration.
- `vendor/`: (Reference only) External SDKs and legacy C# implementation (Excluded from tracking).
- `README.md`: This documentation.

---

## ⚖️ License
This project is licensed under either the Apache License, Version 2.0 or the MIT license at your option.
