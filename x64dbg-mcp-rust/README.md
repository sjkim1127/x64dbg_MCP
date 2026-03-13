# x64dbg-mcp-rust

An advanced **Model Context Protocol (MCP)** server implemented as an x64dbg plugin in Rust. This plugin exposes the full power of x64dbg to AI assistants (like Claude, Gemini, or any MCP client), enabling automated reverse engineering, malware analysis, and debugging via natural language.

---

## 🚀 Key Features

- **Native Rust Architecture**: High-performance, asynchronous core using `Tokio`.
- **MCP SSE Support**: Real-time communication with MCP clients using Server-Sent Events.
- **Thread Safety**: Uses a task-queue architecture to safely interface with x64dbg's main GUI thread.
- **Dynamic Scripting**: Integrated `Rhai` script engine for rapid automation without recompiling.
- **Pro-Level Analysis Tools**: Direct access to lower-level SDK functions for advanced research.

---

## 🛠 Available Tools (40+)

The plugin provides a comprehensive suite of tools Categorized for professional research:

### 1. Basic Debugging & Control

- `ExecuteCommand`: Run native x64dbg commands.
- `DebugRun` / `Pause` / `Stop`: Full execution control.
- `DebugStepIn` / `StepOver` / `StepOut`: Granular stepping.
- `GetThreads` / `GetModules` / `GetCallStack`: Process state introspection.

### 2. Memory & Register Analysis

- `ReadMemory`: Byte-level memory access.
- `GetRegisters` / `SetRegister`: Full access to CPU state.
- `AssembleMem`: Write instructions directly to memory.
- `PatternFindMem`: Find binary patterns/signatures.

### 3. Advanced Analytical Tools (New!)

- **`GetXrefs`**: Track all cross-references to a specific address.
- **`GetTcpConnections`**: Monitor active network sockets of the target.
- **`GetHandles`**: Enumerate open files, registry keys, and other system handles.
- **`GetHeaps`**: Analyze dynamic memory allocation.
- **`GetWindows`**: Inspect the target's GUI window structure and handles.
- **`GetPebTeb`**: Retrieve PEB and TEB for anti-debugging and system analysis.
- **`DisassembleRange`**: Bulk disassembly for quick analysis.

### 4. Advanced Automation

- `AnalyzeFunction`: CFG-based function analysis with cross-references.
- `StructDumpMem`: Parse memory into C-style structures with alignment data.
- `YaraScanMem`: Scan memory using custom YARA rules (powered by `boreal`).
- `ExecuteScript`: Run Rhai scripts for complex, automated workflows.

---

## 🔨 Build & Installation

### Requirements

- Windows (x64)
- [Rust](https://rustup.rs/) (Stable)
- [x64dbg](https://x64dbg.com/) installed.

### Setup

1. Clone the repository.
2. Ensure you have the `x64dbg-pluginsdk` in your search path or vendor directory.
3. Build the plugin:

   ```bash
   cargo build --release
   ```

4. Copy the resulting `.dp64` (or `.dll`) to your x64dbg `plugins` folder.

---

## ⚙️ CI/CD & Automation

This project utilizes **GitHub Actions** for continuous integration and delivery:

- **Build Matrix**: Automated builds on `windows-latest`.
- **Linting**: Continuous code quality checks (`rustfmt`, `clippy`).
- **Artifact Storage**: Compiled binaries are kept as workflow artifacts.
- **Auto-Release**: Pushing a tag (e.g., `v1.0.0`) triggers an automated GitHub Release with the plugin attached.

---

## 🛡 Security Note

This plugin exposes low-level system access via the MCP protocol. Ensure you are running the MCP server in a controlled environment when connecting to external AI models.

---

## 📝 License

MIT / Apache 2.0
