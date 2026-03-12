import re

with open("src/mcp/tools.rs", "r") as f:
    content = f.read()

# Fix parse_hex
content = re.sub(
    r"pub fn parse_hex\(s: &str\) -> Result<crate::x64dbg::duint, ErrorData> \{\n\s*crate::x64dbg::duint::from_str_radix\(s\.trim_start_matches\(\"0x\"\), 16\)\n\s*\.map_err\(\|\_\| ErrorData::invalid_params\(format!\(\"Invalid hex format: \{\}\", s\), None\)\)\n\}",
    r"pub fn parse_hex(s: &str) -> Result<usize, ErrorData> {\n    usize::from_str_radix(s.trim_start_matches(\"0x\"), 16)\n        .map_err(|_| ErrorData::invalid_params(format!(\"Invalid hex format: {}\", s), None))\n}",
    content
)

# Remove `as usize` casts when calling parse_hex
content = re.sub(r"(parse_hex\(.*?\)\?)\s+as\s+usize", r"\1", content)
content = content.replace("unwrap_or(256) as usize", "unwrap_or(256)")

# Fix internal_error single arg to two args
content = re.sub(r"ErrorData::internal_error\((.*?)\)", r"ErrorData::internal_error(\1, None)", content)

with open("src/mcp/tools.rs", "w") as f:
    f.write(content)
