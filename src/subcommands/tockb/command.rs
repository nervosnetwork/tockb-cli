use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, DepType, TransactionView},
    h256,
    packed::{self, Byte32, CellDep, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches};
use int_enum::IntEnum;
use molecule::prelude::Byte;
use serde::{Deserialize, Serialize};
use tockb_types::{generated::tockb_cell_data::ToCKBCellData, tockb_cell};

use super::config::{OutpointConf, ScriptConf, ScriptsConf, Settings};
use crate::plugin::{KeyStoreHandler, PluginManager, SignTarget};
pub use crate::subcommands::wallet::start_index_thread;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    index::IndexController,
    other::{
        check_capacity, get_arg_value, get_live_cell_with_cache, get_max_mature_number,
        get_network_type, get_privkey_signer, is_mature, read_password, sync_to_tip,
    },
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, MULTISIG_TYPE_HASH, ONE_CKB},
    wallet::DerivationPath,
    Address, AddressPayload, GenesisInfo, HttpRpcClient, MultisigConfig, SignerFn, Since,
    SinceType, TxHelper, SECP256K1,
};

// Max derived change address to search
const DERIVE_CHANGE_ADDRESS_MAX_LEN: u32 = 10000;

pub struct ToCkbSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
}

impl<'a> ToCkbSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
    ) -> ToCkbSubCommand<'a> {
        ToCkbSubCommand {
            rpc_client,
            plugin_mgr,
            genesis_info,
            index_dir,
            index_controller,
            wait_for_sync,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(0)?
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
    where
        F: FnOnce(IndexDatabase) -> T,
    {
        if self.wait_for_sync {
            sync_to_tip(&self.index_controller)?;
        }
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir, genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db))
        })
        .map_err(|_err| {
            format!(
                "Index database may not ready, sync process: {}",
                self.index_controller.state().read().to_string()
            )
        })
    }

    pub fn subcommand() -> App<'static> {
        App::new("tockb")
            .about("tockb cli tools")
            .arg(
                Arg::with_name("config-path")
                    .long("config-path")
                    .short('c')
                    .takes_value(true)
                    .default_value(".tockb-config.toml")
                    .about("tockb config path"),
            )
            .subcommands(vec![
                App::new("init").about("init tockb config").arg(
                    Arg::with_name("force")
                        .long("force")
                        .short('f')
                        .about("force init config, it may overwrite existing one"),
                ),
                App::new("dev-deploy-sudt")
                    .about("init tockb config, should only be used for development")
                    .arg(arg::privkey_path().required(true))
                    .arg(
                        Arg::with_name("sudt-path")
                            .long("sudt-path")
                            .takes_value(true)
                            .default_value("../tests/deps/simple_udt"),
                    ),
                App::new("dev-set-price-oracle")
                    .about("set price oracle and write the outpoint to config")
                    .arg(arg::privkey_path().required(true))
                    .arg(Arg::with_name("price").long("price").takes_value(true)),
                App::new("deploy")
                    .about("deploy toCKB scripts")
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(
                        Arg::with_name("typescript-path")
                            .long("typescript-path")
                            .short('t')
                            .takes_value(true)
                            .default_value("../build/release/toCKB-typescript")
                            .about("typescript path"),
                    )
                    .arg(
                        Arg::with_name("lockscript-path")
                            .long("lockscript-path")
                            .short('l')
                            .takes_value(true)
                            .default_value("../build/release/toCKB-lockscript")
                            .about("lockscript path"),
                    ),
                App::new("deposit_request")
                    .about("create a cell to request deposit")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(
                        arg::from_account()
                            .required_unless(arg::privkey_path().get_name())
                            .conflicts_with(arg::privkey_path().get_name()),
                    )
                    .arg(arg::from_locked_address())
                    .arg(arg::tx_fee().required(true))
                    .arg(arg::derive_receiving_address_length())
                    .arg(
                        arg::derive_change_address().conflicts_with(arg::privkey_path().get_name()),
                    )
                    .arg(Arg::from("-p --pledge=[pledge] 'pledge'"))
                    .arg(Arg::from("-l --lot_size=[lot_size] 'lot_size'"))
                    .arg(Arg::from("-k --kind=[kind] 'kind'")),
            ])
    }

    pub fn set_price_oracle(&mut self, args: SetPriceOracleArgs) -> Result<Output, String> {
        let SetPriceOracleArgs {
            price,
            config_path,
            privkey_path,
            skip_check,
        } = args;
        let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
        let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
        let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);

        let to_capacity = Capacity::bytes(100)
            .map_err(|e| format!("{}", e))?
            .as_u64();
        let output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output(output, price.to_le_bytes().to_vec().into());
        let tx_fee: u64 = CapacityParser.parse("0.0001")?.into();
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        let mut settings = Settings::new(&config_path)
            .map_err(|e| format!("failed to load config from {}, err: {}", &config_path, e))?;
        settings.price_oracle.outpoint = OutpointConf {
            tx_hash: tx_hash.to_string(),
            index: 0,
        };
        settings.write(&config_path)?;
        Ok(Output::new_output(format!(
            "price oracle config written to {:?}",
            &config_path
        )))
    }
    pub fn deploy_sudt(&mut self, args: DeploySudtArgs) -> Result<Output, String> {
        let DeploySudtArgs {
            sudt_path,
            config_path,
            privkey_path,
            skip_check,
        } = args;
        let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
        let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
        let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);

        let sudt_bin = std::fs::read(&sudt_path).map_err(|e| format!("{}", e))?;
        let sudt_code_hash = blake2b_256(&sudt_bin);
        let extra_capacity = 62;
        let to_capacity = Capacity::bytes(sudt_bin.len() + extra_capacity)
            .map_err(|e| format!("{}", e))?
            .as_u64();
        let sudt_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output(sudt_output, sudt_bin.into());
        let tx_fee: u64 = CapacityParser.parse("0.0001")?.into();
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        let mut settings = Settings::new(&config_path)
            .map_err(|e| format!("failed to load config from {}, err: {}", &config_path, e))?;
        settings.sudt_script = ScriptConf {
            code_hash: hex::encode(&sudt_code_hash),
            outpoint: OutpointConf {
                tx_hash: tx_hash.to_string(),
                index: 0,
            },
        };
        settings.write(&config_path)?;
        Ok(Output::new_output(format!(
            "sudt config written to {:?}",
            &config_path
        )))
    }

    pub fn deploy(&mut self, args: DeployRequestArgs) -> Result<Output, String> {
        let DeployRequestArgs {
            lockscript_path,
            typescript_path,
            config_path,
            tx_fee,
            privkey_path,
            skip_check,
        } = args;

        let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
        let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
        let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);

        let typescript_bin = std::fs::read(&typescript_path).map_err(|e| format!("{}", e))?;
        let lockscript_bin = std::fs::read(&lockscript_path).map_err(|e| format!("{}", e))?;
        let typescript_code_hash = blake2b_256(&typescript_bin);
        let lockscript_code_hash = blake2b_256(&lockscript_bin);
        let extra_capacity = 62;
        let to_lock_capacity = Capacity::bytes(lockscript_bin.len() + extra_capacity)
            .map_err(|e| format!("{}", e))?
            .as_u64();
        let to_type_capacity = Capacity::bytes(typescript_bin.len() + extra_capacity)
            .map_err(|e| format!("{}", e))?
            .as_u64();
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let lock_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_lock_capacity).pack())
            .lock((&from_address_payload).into())
            .build();
        let type_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_type_capacity).pack())
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output(type_output, typescript_bin.into());
        helper.add_output(lock_output, lockscript_bin.into());
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        let mut settings = Settings::new(&config_path)
            .map_err(|e| format!("failed to load config from {}, err: {}", &config_path, e))?;
        settings.lockscript = ScriptConf {
            code_hash: hex::encode(&lockscript_code_hash),
            outpoint: OutpointConf {
                tx_hash: tx_hash.to_string(),
                index: 1,
            },
        };
        settings.typescript = ScriptConf {
            code_hash: hex::encode(&typescript_code_hash),
            outpoint: OutpointConf {
                tx_hash: tx_hash.to_string(),
                index: 0,
            },
        };
        let resp = ScriptsConf {
            typescript: settings.typescript.clone(),
            lockscript: settings.lockscript.clone(),
        };
        let s = toml::to_string(&resp).expect("toml serde error");
        println!("scripts config: \n\n{}", &s);
        settings.write(&config_path)?;
        println!("scripts config written to {:?}", &config_path);
        Ok(Output::new_output("deploy finished!"))
    }

    pub fn deposit_request(
        &mut self,
        args: DepositRequestArgs,
        skip_check: bool,
        settings: Settings,
    ) -> Result<TransactionView, String> {
        let DepositRequestArgs {
            privkey_path,
            from_account,
            from_locked_address,
            password,
            derive_receiving_address_length,
            derive_change_address,
            tx_fee,

            pledge,
            kind,
            lot_size,
        } = args;

        let network_type = get_network_type(self.rpc_client)?;
        let from_privkey: Option<PrivkeyWrapper> = privkey_path
            .map(|input| PrivkeyPathParser.parse(&input))
            .transpose()?;
        let from_account: Option<H160> = from_account
            .map(|input| {
                FixedHashParser::<H160>::default()
                    .parse(&input)
                    .or_else(|err| {
                        let result: Result<Address, String> = AddressParser::new_sighash()
                            .set_network(network_type)
                            .parse(&input);
                        result
                            .map(|address| H160::from_slice(&address.payload().args()).unwrap())
                            .map_err(|_| err)
                    })
            })
            .transpose()?;
        let from_locked_address: Option<Address> = from_locked_address
            .map(|input| {
                AddressParser::default()
                    .set_network(network_type)
                    .set_full_type(MULTISIG_TYPE_HASH.clone())
                    .parse(&input)
            })
            .transpose()?;
        let to_capacity = pledge * 100_000_000;
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let receiving_address_length: u32 = derive_receiving_address_length
            .map(|input| FromStrParser::<u32>::default().parse(&input))
            .transpose()?
            .unwrap_or(1000);
        let last_change_address_opt: Option<Address> = derive_change_address
            .map(|input| {
                AddressParser::default()
                    .set_network(network_type)
                    .parse(&input)
            })
            .transpose()?;

        let (from_address_payload, password) = if let Some(from_privkey) = from_privkey.as_ref() {
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, from_privkey);
            (AddressPayload::from_pubkey(&from_pubkey), None)
        } else {
            let password = if let Some(password) = password {
                Some(password)
            } else if self.plugin_mgr.keystore_require_password() {
                Some(read_password(false, None)?)
            } else {
                None
            };
            (
                AddressPayload::from_pubkey_hash(from_account.unwrap()),
                password,
            )
        };
        let from_address = Address::new(network_type, from_address_payload.clone());

        if let Some(from_locked_address) = from_locked_address.as_ref() {
            let args = from_locked_address.payload().args();
            let err_prefix = "Invalid from-locked-address's args";
            if args.len() != 28 {
                return Err(format!("{}: invalid {}", err_prefix, args.len()));
            }
            let mut since_bytes = [0u8; 8];
            since_bytes.copy_from_slice(&args[20..]);
            let since = Since::from_raw_value(u64::from_le_bytes(since_bytes));
            if !since.flags_is_valid() {
                return Err(format!("{}: invalid since flags", err_prefix));
            }
            if !since.is_absolute() {
                return Err(format!("{}: only support absolute since value", err_prefix));
            }
            if since.extract_metric().map(|(ty, _)| ty) != Some(SinceType::EpochNumberWithFraction)
            {
                return Err(format!("{}: only support epoch since value", err_prefix));
            }
        }

        let genesis_info = self.genesis_info()?;

        // For check index database is ready
        self.with_db(|_| ())?;
        let index_dir = self.index_dir.clone();
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();

        // The lock hashes for search live cells
        let mut lock_hashes = vec![Script::from(&from_address_payload).calc_script_hash()];
        let mut helper = TxHelper::default();

        let from_lock_arg = H160::from_slice(from_address.payload().args().as_ref()).unwrap();
        let mut path_map: HashMap<H160, DerivationPath> = Default::default();
        let (change_address_payload, change_path) =
            if let Some(last_change_address) = last_change_address_opt {
                // Behave like HD wallet
                let change_last =
                    H160::from_slice(last_change_address.payload().args().as_ref()).unwrap();
                let key_set = self.plugin_mgr.keystore_handler().derived_key_set(
                    from_lock_arg.clone(),
                    receiving_address_length,
                    change_last.clone(),
                    DERIVE_CHANGE_ADDRESS_MAX_LEN,
                    None,
                )?;
                let mut change_path_opt = None;
                for (path, hash160) in key_set.external.iter().chain(key_set.change.iter()) {
                    if hash160 == &change_last {
                        change_path_opt = Some(path.clone());
                    }
                    path_map.insert(hash160.clone(), path.clone());
                    let payload = AddressPayload::from_pubkey_hash(hash160.clone());
                    lock_hashes.push(Script::from(&payload).calc_script_hash());
                }
                (
                    last_change_address.payload().clone(),
                    change_path_opt.expect("change path not exists"),
                )
            } else {
                (from_address.payload().clone(), DerivationPath::empty())
            };

        if let Some(from_locked_address) = from_locked_address.as_ref() {
            lock_hashes.insert(
                0,
                Script::from(from_locked_address.payload()).calc_script_hash(),
            );
            for lock_arg in std::iter::once(&from_lock_arg).chain(path_map.keys()) {
                let mut sighash_addresses = Vec::default();
                sighash_addresses.push(AddressPayload::from_pubkey_hash(lock_arg.clone()));
                let require_first_n = 0;
                let threshold = 1;
                let cfg = MultisigConfig::new_with(sighash_addresses, require_first_n, threshold)?;
                if cfg.hash160().as_bytes() == &from_locked_address.payload().args()[0..20] {
                    helper.add_multisig_config(cfg);
                    break;
                }
            }
            if helper.multisig_configs().is_empty() {
                return Err(String::from(
                    "from-locked-address is not created from the key or derived keys",
                ));
            }
        }

        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let mut from_capacity = 0;
        let mut infos: Vec<LiveCellInfo> = Default::default();
        let mut terminator = |_, info: &LiveCellInfo| {
            if from_capacity >= to_capacity + tx_fee {
                (true, false)
            } else if info.type_hashes.is_none()
                && info.data_bytes == 0
                && is_mature(info, max_mature_number)
            {
                from_capacity += info.capacity;
                infos.push(info.clone());
                (from_capacity >= to_capacity + tx_fee, false)
            } else {
                (false, false)
            }
        };
        if self.wait_for_sync {
            sync_to_tip(&self.index_controller)?;
        }
        if let Err(err) = with_index_db(&index_dir, genesis_hash.unpack(), |backend, cf| {
            IndexDatabase::from_db(backend, cf, network_type, genesis_info_clone, false)
                .map(|db| {
                    for lock_hash in lock_hashes {
                        db.get_live_cells_by_lock(lock_hash, None, &mut terminator);
                    }
                })
                .map_err(Into::into)
        }) {
            return Err(format!(
                "Index database may not ready, sync process: {}, error: {}",
                self.index_controller.state().read().to_string(),
                err.to_string(),
            ));
        }

        if tx_fee > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB".to_string());
        }
        if to_capacity + tx_fee > from_capacity {
            return Err(format!(
                "Capacity(mature) not enough: {} => {}",
                from_address, from_capacity,
            ));
        }

        let rest_capacity = from_capacity - to_capacity - tx_fee;
        if rest_capacity < MIN_SECP_CELL_CAPACITY && tx_fee + rest_capacity > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB, please change to-capacity value to adjust".to_string());
        }

        let rpc_url = self.rpc_client.url().to_string();
        let keystore = self.plugin_mgr.keystore_handler();
        let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
            Default::default();
        let mut get_live_cell_fn = |out_point: OutPoint, with_data: bool| {
            get_live_cell_with_cache(&mut live_cell_cache, self.rpc_client, out_point, with_data)
                .map(|(output, _)| output)
        };
        for info in &infos {
            helper.add_input(
                info.out_point(),
                None,
                &mut get_live_cell_fn,
                &genesis_info,
                skip_check,
            )?;
        }
        let lockscript_out_point = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(&hex::decode(settings.lockscript.outpoint.tx_hash).unwrap())
                    .unwrap(),
            )
            .index(settings.lockscript.outpoint.index.pack())
            .build();
        let typescript_out_point = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(&hex::decode(settings.typescript.outpoint.tx_hash).unwrap())
                    .unwrap(),
            )
            .index(settings.typescript.outpoint.index.pack())
            .build();
        let typescript_cell_dep = CellDep::new_builder()
            .out_point(typescript_out_point)
            .dep_type(DepType::Code.into())
            .build();
        let lockscript_cell_dep = CellDep::new_builder()
            .out_point(lockscript_out_point)
            .dep_type(DepType::Code.into())
            .build();
        helper.transaction = helper
            .transaction
            .as_advanced_builder()
            .cell_dep(typescript_cell_dep)
            .cell_dep(lockscript_cell_dep)
            .build();
        let tockb_data = ToCKBCellData::new_builder()
            .status(Byte::new(tockb_cell::ToCKBStatus::Initial.int_value()))
            .lot_size(Byte::new(lot_size))
            .build()
            .as_bytes();
        check_capacity(to_capacity, tockb_data.len())?;
        let lockscript_hash =
            hex::decode(settings.lockscript.code_hash).expect("wrong lockscript code hash config");
        let typescript_hash =
            hex::decode(settings.typescript.code_hash).expect("wrong typescript code hash config");
        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&typescript_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(vec![kind].pack())
            .build();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(&lockscript_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript_hash.pack())
            .build();
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .type_(Some(typescript).pack())
            .lock(lockscript)
            .build();
        helper.add_output(to_output, tockb_data);
        if rest_capacity >= MIN_SECP_CELL_CAPACITY {
            let change_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(rest_capacity).pack())
                .lock((&change_address_payload).into())
                .build();
            helper.add_output(change_output, Bytes::default());
        }

        let signer = if let Some(from_privkey) = from_privkey {
            get_privkey_signer(from_privkey)
        } else {
            let new_client = HttpRpcClient::new(rpc_url);
            get_keystore_signer(
                keystore,
                new_client,
                change_path,
                path_map,
                from_lock_arg,
                password,
            )
        };
        for (lock_arg, signature) in
            helper.sign_inputs(signer, &mut get_live_cell_fn, skip_check)?
        {
            helper.add_signature(lock_arg, signature)?;
        }
        let tx = helper.build_tx(&mut get_live_cell_fn, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        Ok(tx)
    }

    fn supply_capacity(
        &mut self,
        helper: &mut TxHelper,
        tx_fee: u64,
        privkey_path: String,
        skip_check: bool,
    ) -> Result<TransactionView, String> {
        let network_type = get_network_type(self.rpc_client)?;
        let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
        let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
        let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);
        let lock_hash = Script::from(&from_address_payload).calc_script_hash();
        let from_address = Address::new(network_type, from_address_payload.clone());

        if self.wait_for_sync {
            sync_to_tip(&self.index_controller)?;
        }
        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let index_dir = self.index_dir.clone();
        let genesis_info = self.genesis_info()?;
        self.with_db(|_| ())?;

        let mut live_cell_cache: HashMap<(OutPoint, bool), (CellOutput, Bytes)> =
            Default::default();
        let mut get_live_cell_fn = |out_point: OutPoint, with_data: bool| {
            get_live_cell_with_cache(&mut live_cell_cache, self.rpc_client, out_point, with_data)
                .map(|(output, _)| output)
        };
        let from_capacity: u64 = helper
            .transaction
            .inputs()
            .into_iter()
            .map(|input| {
                let cap: u64 = get_live_cell_fn(input.previous_output(), false)
                    .expect("input not exist")
                    .capacity()
                    .unpack();
                cap
            })
            .sum();
        let to_capacity: u64 = helper
            .transaction
            .outputs()
            .into_iter()
            .map(|output| {
                let cap: u64 = output.capacity().unpack();
                cap
            })
            .sum();

        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let mut from_capacity = from_capacity;
        let mut infos: Vec<LiveCellInfo> = Default::default();
        let mut terminator = |_, info: &LiveCellInfo| {
            if from_capacity >= to_capacity + tx_fee {
                (true, false)
            } else if info.type_hashes.is_none()
                && info.data_bytes == 0
                && is_mature(info, max_mature_number)
            {
                from_capacity += info.capacity;
                infos.push(info.clone());
                (from_capacity >= to_capacity + tx_fee, false)
            } else {
                (false, false)
            }
        };
        if let Err(err) = with_index_db(&index_dir, genesis_hash.unpack(), |backend, cf| {
            IndexDatabase::from_db(backend, cf, network_type, genesis_info_clone, false)
                .map(|db| {
                    db.get_live_cells_by_lock(lock_hash, None, &mut terminator);
                })
                .map_err(Into::into)
        }) {
            return Err(format!(
                "Index database may not ready, sync process: {}, error: {}",
                self.index_controller.state().read().to_string(),
                err.to_string(),
            ));
        }

        if tx_fee > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB".to_string());
        }
        if to_capacity + tx_fee > from_capacity {
            return Err(format!(
                "Capacity(mature) not enough: {} => {}",
                from_address, from_capacity,
            ));
        }

        let rest_capacity = from_capacity - to_capacity - tx_fee;
        if rest_capacity < MIN_SECP_CELL_CAPACITY && tx_fee + rest_capacity > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB, please change to-capacity value to adjust".to_string());
        }

        for info in &infos {
            helper.add_input(
                info.out_point(),
                None,
                &mut get_live_cell_fn,
                &genesis_info,
                skip_check,
            )?;
        }
        if rest_capacity >= MIN_SECP_CELL_CAPACITY {
            let change_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(rest_capacity).pack())
                .lock((&from_address_payload).into())
                .build();
            helper.add_output(change_output, Bytes::default());
        }
        let signer = get_privkey_signer(from_privkey);
        for (lock_arg, signature) in
            helper.sign_inputs(signer, &mut get_live_cell_fn, skip_check)?
        {
            helper.add_signature(lock_arg, signature)?;
        }
        let tx = helper.build_tx(&mut get_live_cell_fn, skip_check)?;
        Ok(tx)
    }
}

impl<'a> CliSubCommand for ToCkbSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let config_path = get_arg_value(matches, "config-path")?;
        match matches.subcommand() {
            ("init", Some(m)) => {
                if std::path::Path::new(&config_path).exists() && !m.is_present("force") {
                    return Err(format!("tockb config already exists at {}, use `-f` in command if you want to overwrite it", &config_path));
                }
                Settings::default().write(&config_path)?;
                Ok(Output::new_output(format!(
                    "tockb config written to {}",
                    config_path
                )))
            }
            ("dev-deploy-sudt", Some(m)) => {
                let args = DeploySudtArgs {
                    config_path,
                    sudt_path: get_arg_value(m, "sudt-path")?,
                    privkey_path: get_arg_value(m, "privkey-path")?,
                    skip_check: false,
                };
                self.deploy_sudt(args)
            }
            ("dev-set-price-oracle", Some(m)) => {
                let args = SetPriceOracleArgs {
                    config_path,
                    privkey_path: get_arg_value(m, "privkey-path")?,
                    skip_check: false,
                    price: get_arg_value(m, "price")?
                        .parse()
                        .map_err(|e| format!("parse price error: {}", e))?,
                };
                self.set_price_oracle(args)
            }
            ("deploy", Some(m)) => {
                let args = DeployRequestArgs {
                    tx_fee: get_arg_value(m, "tx-fee")?,
                    lockscript_path: get_arg_value(m, "lockscript-path")?,
                    typescript_path: get_arg_value(m, "typescript-path")?,
                    privkey_path: get_arg_value(m, "privkey-path")?,
                    config_path,
                    skip_check: false,
                };
                self.deploy(args)
            }
            ("deposit_request", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = DepositRequestArgs {
                    pledge: get_arg_value(m, "pledge")?
                        .parse()
                        .map_err(|_e| "parse pledge error".to_owned())?,
                    kind: get_arg_value(m, "kind")?
                        .parse()
                        .map_err(|_e| "parse kind error".to_owned())?,
                    lot_size: get_arg_value(m, "lot_size")?
                        .parse()
                        .map_err(|_e| "parse lot_size error".to_owned())?,
                    privkey_path: m.value_of("privkey-path").map(|s| s.to_string()),
                    from_account: m.value_of("from-account").map(|s| s.to_string()),
                    from_locked_address: m.value_of("from-locked-address").map(|s| s.to_string()),
                    password: None,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                    derive_receiving_address_length: Some(get_arg_value(
                        m,
                        "derive-receiving-address-length",
                    )?),
                    derive_change_address: m
                        .value_of("derive-change-address")
                        .map(|s| s.to_string()),
                };
                let tx = self.deposit_request(args, false, settings)?;
                if debug {
                    let rpc_tx_view = json_types::TransactionView::from(tx);
                    Ok(Output::new_output(rpc_tx_view))
                } else {
                    let tx_hash: H256 = tx.hash().unpack();
                    Ok(Output::new_output(tx_hash))
                }
            }
            _ => Err(Self::subcommand().generate_usage()),
        }
    }
}

fn get_keystore_signer(
    keystore: KeyStoreHandler,
    mut client: HttpRpcClient,
    change_path: DerivationPath,
    path_map: HashMap<H160, DerivationPath>,
    account: H160,
    password: Option<String>,
) -> SignerFn {
    Box::new(
        move |lock_args: &HashSet<H160>, message: &H256, tx: &json_types::Transaction| {
            let path: &[_] = if lock_args.contains(&account) {
                &[]
            } else {
                match lock_args.iter().find_map(|lock_arg| path_map.get(lock_arg)) {
                    None => return Ok(None),
                    Some(path) => path.as_ref(),
                }
            };
            if message == &h256!("0x0") {
                return Ok(Some([0u8; 65]));
            }
            let sign_target = if keystore.has_account_in_default(account.clone())? {
                SignTarget::AnyData(Default::default())
            } else {
                let inputs = tx
                    .inputs
                    .iter()
                    .map(|input| {
                        let tx_hash = &input.previous_output.tx_hash;
                        client
                            .get_transaction(tx_hash.clone())?
                            .map(|tx_with_status| tx_with_status.transaction.inner)
                            .map(packed::Transaction::from)
                            .map(json_types::Transaction::from)
                            .ok_or_else(|| format!("transaction not exists: {:x}", tx_hash))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                SignTarget::Transaction {
                    tx: tx.clone(),
                    inputs,
                    change_path: change_path.to_string(),
                }
            };
            let data = keystore.sign(
                account.clone(),
                path,
                message.clone(),
                sign_target,
                password.clone(),
                true,
            )?;
            if data.len() != 65 {
                Err(format!(
                    "Invalid signature data lenght: {}, data: {:?}",
                    data.len(),
                    data
                ))
            } else {
                let mut data_bytes = [0u8; 65];
                data_bytes.copy_from_slice(&data[..]);
                Ok(Some(data_bytes))
            }
        },
    )
}

#[derive(Clone, Debug)]
pub struct SetPriceOracleArgs {
    pub privkey_path: String,
    pub config_path: String,
    pub skip_check: bool,
    pub price: u64,
}

#[derive(Clone, Debug)]
pub struct DeploySudtArgs {
    pub privkey_path: String,
    pub sudt_path: String,
    pub config_path: String,
    pub skip_check: bool,
}

#[derive(Clone, Debug)]
pub struct DeployRequestArgs {
    pub privkey_path: String,
    pub lockscript_path: String,
    pub typescript_path: String,
    pub config_path: String,
    pub tx_fee: String,
    pub skip_check: bool,
}

#[derive(Clone, Debug)]
pub struct DepositRequestArgs {
    pub privkey_path: Option<String>,
    pub from_account: Option<String>,
    pub from_locked_address: Option<String>,
    pub password: Option<String>,
    pub derive_receiving_address_length: Option<String>,
    pub derive_change_address: Option<String>,
    pub tx_fee: String,

    pub pledge: u64,
    pub lot_size: u8,
    pub kind: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveCells {
    pub live_cells: Vec<LiveCell>,
    pub current_count: u32,
    pub current_capacity: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveCell {
    pub info: LiveCellInfo,
    pub mature: bool,
}
