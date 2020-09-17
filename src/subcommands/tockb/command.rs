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
use int_enum::IntEnum;
use molecule::prelude::Byte;
use serde::{Deserialize, Serialize};
use tockb_types::{
    generated::{basic, tockb_cell_data::ToCKBCellData},
    tockb_cell,
};

use super::config::{OutpointConf, ScriptConf, ScriptsConf, Settings};
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
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("--user-lockscript-addr=[user-lockscript-addr] 'user-lockscript-addr'"))
                    .arg(Arg::from("-p --pledge=[pledge] 'pledge'"))
                    .arg(Arg::from("-l --lot_size=[lot_size] 'lot_size'"))
                    .arg(Arg::from("-k --kind=[kind] 'kind'")),
                App::new("bonding")
                    .about("bonding signer")
                    .arg(arg::privkey_path().required_unless(arg::from_account().get_name()))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("--lock_address=[lock_address] 'lock_address'"))
                    .arg(Arg::from("--signer_lockscript_addr=[signer_lockscript_addr] 'signer_lockscript_addr'"))
                    .arg(Arg::from("-c --cell=[cell] 'cell'"))
                    .arg(Arg::from("-k --kind=[kind] 'kind'")),
            ])
    }

    pub fn get_price_oracle(&mut self, settings: &Settings) -> Result<(CellDep, u128), String> {
        let outpoint = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(
                    &hex::decode(&settings.price_oracle.outpoint.tx_hash)
                        .map_err(|e| format!("invalid price oracle config. err: {}", e))?,
                )
                .map_err(|e| format!("invalid price oracle config. err: {}", e))?,
            )
            .index(settings.price_oracle.outpoint.index.pack())
            .build();
        let cell_dep = CellDep::new_builder()
            .out_point(outpoint.clone())
            .dep_type(DepType::Code.into())
            .build();
        let cell = get_live_cell(self.rpc_client, outpoint, true)?;

        let mut buf = [0u8; 16];
        buf.copy_from_slice(cell.1.as_ref());

        let price = u128::from_le_bytes(buf);
        Ok((cell_dep, price))
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

        let output = CellOutput::new_builder()
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output_with_auto_capacity(output, price.to_le_bytes().to_vec().into());
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
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let lock_output = CellOutput::new_builder()
            .lock((&from_address_payload).into())
            .build();
        let type_output = CellOutput::new_builder()
            .lock((&from_address_payload).into())
            .build();
        let mut helper = TxHelper::default();
        helper.add_output_with_auto_capacity(type_output, typescript_bin.into());
        helper.add_output_with_auto_capacity(lock_output, lockscript_bin.into());
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
            tx_fee,
            user_lockscript_addr,

            pledge,
            kind,
            lot_size,
        } = args;

        let user_lockscript: Script = Address::from_str(&user_lockscript_addr)?.payload().into();
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let to_capacity = pledge * 100_000_000;
        let mut helper = TxHelper::default();

        let lockscript_out_point = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(
                    &hex::decode(settings.lockscript.outpoint.tx_hash)
                        .map_err(|e| format!("invalid lockscript config. err: {}", e))?,
                )
                .map_err(|e| format!("invalid lockscript config. err: {}", e))?,
            )
            .index(settings.lockscript.outpoint.index.pack())
            .build();
        let typescript_out_point = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(
                    &hex::decode(settings.typescript.outpoint.tx_hash)
                        .map_err(|e| format!("invalid typescript config. err: {}", e))?,
                )
                .map_err(|e| format!("invalid typescript config. err: {}", e))?,
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
            .user_lockscript(basic::Script::from_slice(user_lockscript.as_slice()).unwrap())
            .build()
            .as_bytes();
        check_capacity(to_capacity, tockb_data.len())?;
        let lockscript_code_hash =
            hex::decode(settings.lockscript.code_hash).expect("wrong lockscript code hash config");
        let typescript_code_hash =
            hex::decode(settings.typescript.code_hash).expect("wrong typescript code hash config");
        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(vec![kind].pack())
            .build();

        let typescript_hash = typescript.calc_script_hash();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(&lockscript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript_hash.as_bytes().pack())
            .build();
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .type_(Some(typescript).pack())
            .lock(lockscript)
            .build();
        helper.add_output(to_output, tockb_data);
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        Ok(tx)
    }

    pub fn bonding(
        &mut self,
        args: BondingArgs,
        skip_check: bool,
        settings: Settings,
    ) -> Result<TransactionView, String> {
        let BondingArgs {
            privkey_path,
            tx_fee,

            kind,
            cell,
            signer_lockscript_addr,
            lock_address,
        } = args;

        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let signer_lockscript: Script = Address::from_str(&signer_lockscript_addr)?.payload().into();

        let mut helper = TxHelper::default();

        let cell = self.get_ckb_cell(&mut helper, cell, true)?;

        let ckb_cell = cell.0;
        let ckb_cell_data = cell.1;
        let input_capacity: u64 = ckb_cell.capacity().unpack();

        let from_ckb_cell_data = ToCKBCellData::from_slice(ckb_cell_data.as_ref()).unwrap();
        let (price_oracle_dep, price) = self.get_price_oracle(&settings)?;
        let to_capacity = (input_capacity as u128 + 2 * 200 * 100_000_000 + from_ckb_cell_data.lot_size().as_slice()[0] as u128 * 25_000_000 * 150 / (100 * price) * 100_000_000) as u64;

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
            .cell_dep(price_oracle_dep)
            .cell_dep(typescript_cell_dep)
            .cell_dep(lockscript_cell_dep)
            .build();
        let tockb_data = ToCKBCellData::new_builder()
            .status(Byte::new(tockb_cell::ToCKBStatus::Bonded.int_value()))
            .lot_size(from_ckb_cell_data.lot_size())
            .user_lockscript(from_ckb_cell_data.user_lockscript())
            .x_lock_address(basic::Bytes::new_builder()
                                .set(
                                    lock_address
                                        .as_bytes()
                                        .iter()
                                        .map(|c| Byte::new(*c))
                                        .collect::<Vec<_>>()
                                        .into(),
                                )
                                .build())
            .signer_lockscript(basic::Script::from_slice(signer_lockscript.as_slice()).unwrap())
            .build()
            .as_bytes();
        check_capacity(to_capacity, tockb_data.len())?;

        let lockscript_code_hash =
            hex::decode(settings.lockscript.code_hash).expect("wrong lockscript code hash config");
        let typescript_code_hash =
            hex::decode(settings.typescript.code_hash).expect("wrong typescript code hash config");
        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(vec![kind].pack())
            .build();

        let typescript_hash = typescript.calc_script_hash();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(&lockscript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(typescript_hash.as_bytes().pack())
            .build();
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .type_(Some(typescript).pack())
            .lock(lockscript)
            .build();
        helper.add_output(to_output, tockb_data.clone());
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
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

    fn get_ckb_cell(& mut self, helper: &mut TxHelper, cell: String, add_to_input: bool) -> Result<(CellOutput, Bytes), String> {
        let parts: Vec<_> = cell.split('.').collect();
        let original_tx_hash: String = parts[0].to_string();
        let original_tx_output_index: u32 = parts[1].parse::<u32>().unwrap();

        let original_tx_outpoint = OutPoint::new_builder().index(original_tx_output_index.pack()).tx_hash(Byte32::from_slice(&hex::decode(original_tx_hash).unwrap())
            .unwrap()).build();

        if add_to_input {
            let genesis_info = self.genesis_info()?;

            let mut get_live_cell_fn = |out_point: OutPoint, with_data: bool| {
                get_live_cell(self.rpc_client, out_point, with_data)
                    .map(|(output, _)| output)
            };

            helper.add_input(
                original_tx_outpoint.clone(),
                None,
                &mut get_live_cell_fn,
                &genesis_info,
                true,
            )?;
        }

        get_live_cell(
            self.rpc_client,
            original_tx_outpoint,
            true,
        )
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
                    privkey_path: get_arg_value(m, "privkey-path").map(|s| s.to_string())?,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                    user_lockscript_addr: get_arg_value(m, "user-lockscript-addr")?,
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
            ("bonding", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = BondingArgs {
                    cell: get_arg_value(m, "cell").map(|s| s.to_string())?,
                    lock_address: get_arg_value(m, "lock_address").map(|s| s.to_string())?,
                    signer_lockscript_addr: get_arg_value(m, "signer_lockscript_addr").map(|s| s.to_string())?,
                    kind: get_arg_value(m, "kind")?
                        .parse()
                        .map_err(|_e| "parse kind error".to_owned())?,
                    privkey_path: get_arg_value(m, "privkey-path").map(|s| s.to_string())?,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                };
                let tx = self.bonding(args, true, settings)?;
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

#[derive(Clone, Debug)]
pub struct SetPriceOracleArgs {
    pub privkey_path: String,
    pub config_path: String,
    pub skip_check: bool,
    pub price: u128,
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
    pub privkey_path: String,
    pub tx_fee: String,
    pub user_lockscript_addr: String,
    pub pledge: u64,
    pub lot_size: u8,
    pub kind: u8,
}

#[derive(Clone, Debug)]
pub struct BondingArgs {
    pub privkey_path: String,
    pub tx_fee: String,

    pub kind: u8,
    pub cell: String,

    pub lock_address: String,
    pub signer_lockscript_addr: String,
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
