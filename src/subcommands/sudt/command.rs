use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, DepType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};
use clap::{App, Arg, ArgMatches};
use molecule::prelude::Byte;
use tockb_types::{
    config::{UDT_LEN, XT_CELL_CAPACITY},
    generated::tockb_cell_data::ToCKBTypeArgs,
};

use super::config::{OutpointConf, ScriptConf, Settings};
use crate::plugin::PluginManager;
pub use crate::subcommands::wallet::start_index_thread;
use crate::subcommands::{CliSubCommand, Output};
use crate::utils::other::get_live_cell;
use crate::utils::{
    arg,
    arg_parser::{ArgParser, CapacityParser, PrivkeyPathParser},
    index::IndexController,
    other::{
        check_capacity, get_arg_value, get_live_cell_with_cache, get_max_mature_number,
        get_network_type, get_privkey_signer, is_mature, sync_to_tip,
    },
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, ONE_CKB},
    Address, AddressPayload, GenesisInfo, HttpRpcClient, TxHelper, SECP256K1,
};

const TIMEOUT: u64 = 60;

pub struct SudtSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    plugin_mgr: &'a mut PluginManager,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
}

impl<'a> SudtSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        plugin_mgr: &'a mut PluginManager,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        wait_for_sync: bool,
    ) -> SudtSubCommand<'a> {
        SudtSubCommand {
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
        App::new("sudt")
            .about("sudt tools")
            .arg(
                Arg::with_name("config-path")
                    .long("config-path")
                    .short('c')
                    .takes_value(true)
                    .default_value(".tockb-config.toml")
                    .about("tockb config path"),
            )
            .subcommands(vec![
                App::new("dev-deploy-sudt")
                    .about("init tockb config, should only be used for development")
                    .arg(arg::privkey_path().required(true))
                    .arg(
                        Arg::with_name("sudt-path")
                            .long("sudt-path")
                            .takes_value(true)
                            .default_value("../tests/deps/simple_udt"),
                    ),
                App::new("transfer")
                    .about("transfer sudt")
                    .arg(Arg::from("-k --kind=[kind] 'kind'"))
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("-t --to=[to] 'to'"))
                    .arg(Arg::from("--sudt-amount=[sudt-amount] 'sudt-amount'"))
                    .arg(Arg::from("--ckb-amount=[ckb-amount] 'ckb-amount'")),
                App::new("get_balance")
                    .about("get sudt balance")
                    .arg(Arg::from("-k --kind=[kind] 'kind'"))
                    .arg(Arg::from("-a --addr=[addr] 'addr'")),
            ])
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
        let sudt_output = CellOutput::new_builder()
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output_with_auto_capacity(sudt_output, sudt_bin.into());
        let tx_fee: u64 = CapacityParser.parse("0.0001")?.into();
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;
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

    pub fn wait_for_commited(&mut self, tx_hash: H256, timeout: u64) -> Result<(), String> {
        for i in 0..timeout {
            let status = self
                .rpc_client
                .get_transaction(tx_hash.clone())?
                .map(|t| t.tx_status.status);
            println!(
                "waiting for tx {} to be committed, loop index: {}, status: {:?}",
                &tx_hash, i, status
            );
            if status == Some(json_types::Status::Committed) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        return Err(format!("tx {} not commited", &tx_hash));
    }

    pub fn transfer(
        &mut self,
        args: TransferArgs,
        skip_check: bool,
        settings: Settings,
    ) -> Result<TransactionView, String> {
        let TransferArgs {
            kind,
            privkey_path,
            tx_fee,
            to,
            sudt_amount,
            ckb_amount,
        } = args;

        let to_lockscript: Script = Address::from_str(&to)?.payload().into();
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let ckb_amount: u64 = CapacityParser.parse(&ckb_amount)?.into();
        let mut helper = TxHelper::default();

        // add cellDeps
        let outpoints = vec![settings.sudt_script.outpoint];
        self.add_cell_deps(&mut helper, outpoints)?;

        let lockscript_code_hash =
            hex::decode(settings.lockscript.code_hash).expect("wrong lockscript code hash config");
        let typescript_code_hash =
            hex::decode(settings.typescript.code_hash).expect("wrong typescript code hash config");

        let typescript_args = ToCKBTypeArgs::new_builder()
            .xchain_kind(Byte::new(kind))
            .build();

        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript_args.as_bytes().pack())
            .build();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(&lockscript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript.as_slice()[0..54].pack())
            .build();

        {
            let sudt_typescript_code_hash = hex::decode(settings.sudt_script.code_hash)
                .expect("wrong sudt_script code hash config");
            let sudt_typescript = Script::new_builder()
                .code_hash(Byte32::from_slice(&sudt_typescript_code_hash).unwrap())
                .hash_type(DepType::Code.into())
                .args(lockscript.calc_script_hash().as_bytes().pack())
                .build();

            let sudt_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(ckb_amount).pack())
                .type_(Some(sudt_typescript.clone()).pack())
                .lock(to_lockscript)
                .build();

            helper.add_output(sudt_output, sudt_amount.to_le_bytes().to_vec().into());
            check_capacity(ckb_amount, sudt_amount.to_le_bytes().to_vec().len())?;

            self.supply_sudt_amount(
                &mut helper,
                sudt_amount,
                sudt_typescript.clone(),
                privkey_path.clone(),
                skip_check,
            )?;
        }

        // add signature to pay tx fee
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;
        Ok(tx)
    }

    pub fn get_balance(
        &mut self,
        args: GetBalanceArgs,
        settings: Settings,
    ) -> Result<u128, String> {
        let GetBalanceArgs { kind, addr } = args;

        let to_lockscript: Script = Address::from_str(&addr)?.payload().into();

        let sudt_typescript = SudtSubCommand::get_sudt_typescript(kind, settings);
        let sudt_typescript_hash = sudt_typescript.calc_script_hash().unpack();
        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let genesis_info = self.genesis_info()?;
        let genesis_hash = genesis_info.header().hash();
        let index_dir = self.index_dir.clone();
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info_clone = genesis_info.clone();

        self.with_db(|_| ())?;

        let mut total_amount: u128 = 0;
        let mut terminator = |_, info: &LiveCellInfo| {
            if info.type_hashes.is_some()
                && info.type_hashes.as_ref().unwrap().1 == sudt_typescript_hash
                && info.data_bytes == UDT_LEN as u64
                && is_mature(info, max_mature_number)
            {
                total_amount += {
                    let (_, data) = get_live_cell(self.rpc_client, info.out_point(), true)
                        .unwrap_or((CellOutput::default(), Bytes::default()));
                    let mut buf = [0u8; UDT_LEN];
                    buf.copy_from_slice(data.as_ref());
                    u128::from_le_bytes(buf)
                };
            }
            (false, false)
        };

        if let Err(err) = with_index_db(&index_dir, genesis_hash.unpack(), |backend, cf| {
            IndexDatabase::from_db(backend, cf, network_type, genesis_info_clone, false)
                .map(|db| {
                    db.get_live_cells_by_lock(
                        to_lockscript.calc_script_hash(),
                        None,
                        &mut terminator,
                    );
                })
                .map_err(Into::into)
        }) {
            return Err(format!(
                "Index database may not ready, sync process: {}, error: {}",
                self.index_controller.state().read().to_string(),
                err.to_string(),
            ));
        }

        Ok(total_amount)
    }

    fn get_sudt_typescript(kind: u8, settings: Settings) -> Script {
        let lockscript_code_hash =
            hex::decode(settings.lockscript.code_hash).expect("wrong lockscript code hash config");
        let typescript_code_hash =
            hex::decode(settings.typescript.code_hash).expect("wrong typescript code hash config");

        let typescript_args = ToCKBTypeArgs::new_builder()
            .xchain_kind(Byte::new(kind))
            .build();

        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript_args.as_bytes().pack())
            .build();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(&lockscript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript.as_slice()[0..54].pack())
            .build();

        let sudt_typescript_code_hash = hex::decode(settings.sudt_script.code_hash)
            .expect("wrong sudt_script code hash config");
        Script::new_builder()
            .code_hash(Byte32::from_slice(&sudt_typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(lockscript.calc_script_hash().as_bytes().pack())
            .build()
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

    fn add_cell_deps(
        &mut self,
        helper: &mut TxHelper,
        outpoints: Vec<OutpointConf>,
    ) -> Result<(), String> {
        let mut builder = helper.transaction.as_advanced_builder();
        for conf in outpoints {
            let outpoint = OutPoint::new_builder()
                .tx_hash(
                    Byte32::from_slice(
                        &hex::decode(conf.tx_hash)
                            .map_err(|e| format!("invalid OutpointConf config. err: {}", e))?,
                    )
                    .map_err(|e| format!("invalid OutpointConf config. err: {}", e))?,
                )
                .index(conf.index.pack())
                .build();
            builder = builder.cell_dep(
                CellDep::new_builder()
                    .out_point(outpoint)
                    .dep_type(DepType::Code.into())
                    .build(),
            );
        }
        helper.transaction = builder.build();
        Ok(())
    }

    fn supply_sudt_amount(
        &mut self,
        helper: &mut TxHelper,
        need_sudt_amount: u128,
        sudt_typescript: Script,
        privkey_path: String,
        skip_check: bool,
    ) -> Result<(), String> {
        // basic info
        let sudt_typescript_hash = sudt_typescript.calc_script_hash().unpack();
        let index_dir = self.index_dir.clone();
        let network_type = get_network_type(self.rpc_client)?;
        let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
        let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
        let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);
        let lock_hash = Script::from(&from_address_payload).calc_script_hash();
        let from_address = Address::new(network_type, from_address_payload.clone());
        let genesis_info = self.genesis_info()?;
        let genesis_hash = genesis_info.header().hash();
        let genesis_info_clone = genesis_info.clone();
        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        self.with_db(|_| ())?;

        // collect live cellInfos to infos
        let mut infos: Vec<LiveCellInfo> = Default::default();
        let mut collected_amount: u128 = 0;
        let mut terminator = |_, info: &LiveCellInfo| {
            if collected_amount >= need_sudt_amount {
                (true, false)
            } else if info.type_hashes.is_some()
                && info.type_hashes.as_ref().unwrap().1 == sudt_typescript_hash
                && info.data_bytes == UDT_LEN as u64
                && is_mature(info, max_mature_number)
            {
                collected_amount += {
                    let (_, data) = get_live_cell(self.rpc_client, info.out_point(), true)
                        .unwrap_or((CellOutput::default(), Bytes::default()));
                    let mut buf = [0u8; UDT_LEN];
                    buf.copy_from_slice(data.as_ref());
                    u128::from_le_bytes(buf)
                };
                infos.push(info.clone());
                (collected_amount >= need_sudt_amount, false)
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

        if collected_amount < need_sudt_amount {
            return Err(format!(
                "sudt amount(mature) not enough: {} => {}",
                from_address, need_sudt_amount,
            ));
        }

        // add inputs from infos
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

        // add sudt change and return the capacity from the sudt inputs
        if collected_amount > need_sudt_amount {
            let sudt_change_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(XT_CELL_CAPACITY).pack())
                .lock((&from_address_payload).into())
                .type_(Some(sudt_typescript).pack())
                .build();
            let sudt_change_data = (collected_amount - need_sudt_amount)
                .to_le_bytes()
                .to_vec()
                .into();
            helper.add_output(sudt_change_output, sudt_change_data);
        }

        Ok(())
    }
}

impl<'a> CliSubCommand for SudtSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        let config_path = get_arg_value(matches, "config-path")?;
        match matches.subcommand() {
            ("dev-deploy-sudt", Some(m)) => {
                let args = DeploySudtArgs {
                    config_path,
                    sudt_path: get_arg_value(m, "sudt-path")?,
                    privkey_path: get_arg_value(m, "privkey-path")?,
                    skip_check: false,
                };
                self.deploy_sudt(args)
            }
            ("transfer", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = TransferArgs {
                    kind: get_arg_value(m, "kind")?
                        .parse()
                        .map_err(|_e| "parse sudt_amount error".to_owned())?,
                    sudt_amount: get_arg_value(m, "sudt-amount")?
                        .parse()
                        .map_err(|_e| "parse sudt_amount error".to_owned())?,
                    ckb_amount: get_arg_value(m, "ckb-amount")?,
                    to: get_arg_value(m, "to")?,
                    privkey_path: get_arg_value(m, "privkey-path").map(|s| s.to_string())?,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                };
                let tx = self.transfer(args, true, settings)?;
                if debug {
                    let rpc_tx_view = json_types::TransactionView::from(tx);
                    Ok(Output::new_output(rpc_tx_view))
                } else {
                    let tx_hash: H256 = tx.hash().unpack();
                    Ok(Output::new_output(tx_hash))
                }
            }
            ("get_balance", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = GetBalanceArgs {
                    kind: get_arg_value(m, "kind")?
                        .parse()
                        .map_err(|_e| "parse sudt_amount error".to_owned())?,
                    addr: get_arg_value(m, "addr")?,
                };
                let balance = self.get_balance(args, settings)?;
                Ok(Output::new_output(format!("sudt balance {:?}", balance)))
            }
            _ => Err(Self::subcommand().generate_usage()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeploySudtArgs {
    pub privkey_path: String,
    pub sudt_path: String,
    pub config_path: String,
    pub skip_check: bool,
}

#[derive(Clone, Debug)]
pub struct TransferArgs {
    pub kind: u8,
    pub privkey_path: String,
    pub tx_fee: String,
    pub to: String,
    pub sudt_amount: u128,
    pub ckb_amount: String,
}

#[derive(Clone, Debug)]
pub struct GetBalanceArgs {
    pub kind: u8,
    pub addr: String,
}

#[test]
fn test_cmd() {}
