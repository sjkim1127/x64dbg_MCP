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
