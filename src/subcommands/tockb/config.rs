use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct OutpointConf {
    pub tx_hash: String,
    pub index: u64,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct ScriptConf {
    pub code_hash: String,
    pub outpoint: OutpointConf,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct ScriptsConf {
    pub lockscript: ScriptConf,
    pub typescript: ScriptConf,
}