use crate::x64dbg::duint;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ExecuteCommandArgs {
    pub command: String,
}

#[derive(Debug, Deserialize)]
pub struct ReadMemoryArgs {
    pub address: String, // hex string
    pub size: usize,
}

#[derive(Debug, Deserialize)]
pub struct SetRegisterArgs {
    pub register: String,
    pub value: String, // hex string
}

#[derive(Debug, Deserialize)]
pub struct SetBreakpointArgs {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct SetCommentLabelArgs {
    pub address: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct YaraScanMemArgs {
    pub start: String,
    pub size: String,
    pub rule: String,
}

#[derive(Debug, Deserialize)]
pub struct SymbolStringArgs {
    pub module: String,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteScriptArgs {
    pub script: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StructFieldDef {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Deserialize)]
pub struct StructDumpMemArgs {
    pub address: String,
    pub fields: Vec<StructFieldDef>,
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeFunctionArgs {
    pub address: String, // hex string
}

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AnalyzeFunctionResult {
    pub start: String,
    pub end: String,
    pub entry_point: String,
    pub nodes: Vec<CFGNode>,
    pub xrefs: Vec<XRefInfo>,
}

#[derive(Debug, Serialize)]
pub struct XRefInfo {
    pub address: String,
    pub from: String,
    pub type_name: String,
}

#[derive(Debug, Serialize)]
pub struct CFGNode {
    pub start: String,
    pub end: String,
    pub brtrue: String,
    pub brfalse: String,
    pub instruction_count: duint,
    pub is_terminal: bool,
    pub is_split: bool,
    pub has_indirect_call: bool,
    pub instructions: Vec<CFGInstruction>,
    pub exits: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CFGInstruction {
    pub address: String,
    pub bytes: String,
}

#[derive(Debug, Deserialize)]
pub struct MemoryAddressArgs {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct BookmarkArgs {
    pub address: String,
    pub is_bookmark: bool,
}

#[derive(Debug, Deserialize)]
pub struct AssembleMemArgs {
    pub address: String,
    pub instruction: String,
}

#[derive(Debug, Deserialize)]
pub struct PatternFindMemArgs {
    pub start: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize)]
pub struct MiscParseExpressionArgs {
    pub expression: String,
}
