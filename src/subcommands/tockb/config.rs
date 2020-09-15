use super::consts::SCRIPT_CONFIG_FILE;
use config::{Config, ConfigError, Environment, File};
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct OutpointConf {
    pub tx_hash: String,
    pub index: u32,
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

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Settings {
    pub lockscript: ScriptConf,
    pub typescript: ScriptConf,
}

impl Settings {
    pub fn new(config_path: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(File::with_name(
            &std::path::Path::new(config_path)
                .join(SCRIPT_CONFIG_FILE)
                .to_string_lossy(),
        ))?;
        s.merge(Environment::with_prefix("app"))?;
        s.try_into()
    }
}
