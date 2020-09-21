use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, DepType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{App, Arg, ArgMatches};
use int_enum::IntEnum;
use molecule::prelude::Byte;
use serde::{Deserialize, Serialize};
use tockb_types::{
    config::{CKB_UNITS, PLEDGE, SIGNER_FEE_RATE, UDT_LEN, XT_CELL_CAPACITY},
    generated::{
        basic,
        btc_difficulty::BTCDifficulty,
        mint_xt_witness::{BTCSPVProof, MintXTWitness},
        tockb_cell_data::ToCKBCellData,
    },
    BtcExtraView, ToCKBCellDataView, ToCKBStatus, XChainKind, XExtraView,
};

use super::config::{CKBCell, OutpointConf, ScriptConf, ScriptsConf, Settings};
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
                App::new("dev-set-btc-difficulty-cell")
                    .about("set btc difficulty cell and write the outpoint to config")
                    .arg(arg::privkey_path().required(true))
                    .arg(Arg::with_name("difficulty").long("difficulty").takes_value(true)),
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
                    .arg(Arg::from("-k --kind=[kind] 'kind'"))
                    .arg(Arg::from("--cell-path=[cell-path] 'cell-path'").default_value("./.ckb_cell.toml")),
                App::new("bonding")
                    .about("bonding signer")
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("--lock-address=[lock-address] 'lock-address'"))
                    .arg(Arg::from("--signer-lockscript-addr=[signer-lockscript-addr] 'signer-lockscript-addr'"))
                    .arg(Arg::from("--cell-path=[cell-path] 'cell-path'").default_value("./.ckb_cell.toml"))
                    .arg(Arg::from("-c --cell=[cell] 'cell'")),
                App::new("mint_xt")
                    .about("use a bonded toCKB cell and xchain's spv-proof to mint xt cell")
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("--spv-proof=[spv-proof] 'spv-proof'").required(true))
                    .arg(Arg::from("--cell-path=[cell-path] 'cell-path'").default_value("./.ckb_cell.toml"))
                    .arg(Arg::from("-c --cell=[cell] 'cell'")),
                App::new("pre-term_redeem")
                    .about("user redeem X in advance")
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::tx_fee().required(true))
                    .arg(Arg::from("--cell-path=[cell-path] 'cell-path'").default_value("./.ckb_cell.toml"))
                    .arg(Arg::from("-c --cell=[cell] 'cell'"))
                    .arg(Arg::from("--unlock-address"))
                    .arg(Arg::from("--redeemer--lockscript-addr")),
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

        let mut buf = [0u8; UDT_LEN];
        buf.copy_from_slice(cell.1.as_ref());
        let price = u128::from_le_bytes(buf);
        Ok((cell_dep, price))
    }

    pub fn get_btc_difficulty_dep(&mut self, settings: &Settings) -> Result<CellDep, String> {
        let outpoint = OutPoint::new_builder()
            .tx_hash(
                Byte32::from_slice(
                    &hex::decode(&settings.btc_difficulty_cell.outpoint.tx_hash)
                        .map_err(|e| format!("invalid btc_difficulty_cell config. err: {}", e))?,
                )
                .map_err(|e| format!("invalid btc_difficulty_cell config. err: {}", e))?,
            )
            .index(settings.btc_difficulty_cell.outpoint.index.pack())
            .build();
        let cell_dep = CellDep::new_builder()
            .out_point(outpoint.clone())
            .dep_type(DepType::Code.into())
            .build();
        Ok(cell_dep)
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
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;
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

    pub fn set_btc_difficulty_cell(&mut self, args: SetBtcDifficultArgs) -> Result<Output, String> {
        let SetBtcDifficultArgs {
            difficulty,
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

        // 17345997805929 use test
        let dep_data = {
            let data = BTCDifficulty::new_builder()
                .previous(difficulty.to_le_bytes().to_vec().into())
                .current(difficulty.to_le_bytes().to_vec().into())
                .build();
            data.as_bytes()
        };

        helper.add_output_with_auto_capacity(output, dep_data);
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
        settings.btc_difficulty_cell.outpoint = OutpointConf {
            tx_hash: tx_hash.to_string(),
            index: 0,
        };
        settings.write(&config_path)?;
        Ok(Output::new_output(format!(
            "btc difficulty cell config written to {:?}",
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
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;
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
            cell_path,
        } = args;

        let user_lockscript: Script = Address::from_str(&user_lockscript_addr)?.payload().into();
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let to_capacity = pledge * CKB_UNITS;
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
            .status(Byte::new(ToCKBStatus::Initial.int_value()))
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
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;

        ToCkbSubCommand::write_ckb_cell_config(cell_path, tx_hash.to_string(), 0)?;
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
            cell_path,
            cell,
            signer_lockscript_addr,
            lock_address,
        } = args;

        let cell = ToCkbSubCommand::read_ckb_cell_config(cell_path.clone())
            .or(cell.ok_or("cell is none".to_string()))?;
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let signer_lockscript: Script =
            Address::from_str(&signer_lockscript_addr)?.payload().into();

        let mut helper = TxHelper::default();

        let (ckb_cell, ckb_cell_data) = self.get_ckb_cell(&mut helper, cell, true)?;
        let input_capacity: u64 = ckb_cell.capacity().unpack();

        let type_script = ckb_cell
            .type_()
            .to_opt()
            .expect("should return ckb type script");
        let lock_script = ckb_cell.lock();
        let kind: u8 = type_script.args().as_bytes()[0];
        let data_view: ToCKBCellDataView =
            ToCKBCellDataView::new(ckb_cell_data.as_ref(), XChainKind::from_int(kind).unwrap())
                .map_err(|err| format!("Parse to ToCKBCellDataView error: {}", err as i8))?;

        let sudt_amount: u128 = data_view
            .get_lot_xt_amount()
            .map_err(|err| format!("get_lot_xt_amount error: {}", err as i8))?;
        let (_price_oracle_dep, price) = self.get_price_oracle(&settings)?;
        let to_capacity = (input_capacity as u128
            + 2 * 200 * CKB_UNITS as u128
            + sudt_amount * 150 / (100 * price) * CKB_UNITS as u128)
            as u64;

        let outpoints = vec![
            settings.price_oracle.outpoint,
            settings.typescript.outpoint,
            settings.lockscript.outpoint,
        ];
        self.add_cell_deps(&mut helper, outpoints)?;

        let from_ckb_cell_data = ToCKBCellData::from_slice(ckb_cell_data.as_ref())
            .expect("should parse ToCKBCellData correct");
        let tockb_data = ToCKBCellData::new_builder()
            .status(Byte::new(ToCKBStatus::Bonded.int_value()))
            .lot_size(from_ckb_cell_data.lot_size())
            .user_lockscript(from_ckb_cell_data.user_lockscript())
            .x_lock_address(lock_address.as_bytes().to_vec().into())
            .signer_lockscript(basic::Script::from_slice(signer_lockscript.as_slice()).unwrap())
            .build()
            .as_bytes();
        check_capacity(to_capacity, tockb_data.len())?;

        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .type_(Some(type_script).pack())
            .lock(lock_script)
            .build();
        helper.add_output(to_output, tockb_data.clone());
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;

        ToCkbSubCommand::write_ckb_cell_config(cell_path, tx_hash.to_string(), 0)?;
        Ok(tx)
    }

    pub fn mint_xt(
        &mut self,
        args: MintXtArgs,
        skip_check: bool,
        settings: Settings,
    ) -> Result<TransactionView, String> {
        let MintXtArgs {
            privkey_path,
            tx_fee,
            cell_path,
            cell,
            spv_proof,
        } = args;
        let cell = ToCkbSubCommand::read_ckb_cell_config(cell_path.clone())
            .or(cell.ok_or("cell is none".to_string()))?;

        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let mut helper = TxHelper::default();
        if tx_fee > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB".to_string());
        }

        // add cellDeps
        let outpoints = vec![
            settings.btc_difficulty_cell.outpoint,
            settings.lockscript.outpoint,
            settings.typescript.outpoint,
            settings.sudt_script.outpoint,
        ];
        self.add_cell_deps(&mut helper, outpoints)?;

        // get input tockb cell and basic info
        let (from_cell, ckb_cell_data) = self.get_ckb_cell(&mut helper, cell, true)?;
        let from_ckb_cell_data = ToCKBCellData::from_slice(ckb_cell_data.as_ref()).unwrap();

        let (tockb_typescript, kind) = match from_cell.type_().to_opt() {
            Some(script) => (script.clone(), script.args().raw_data().as_ref()[0]),
            None => return Err("typescript of tockb cell is none".to_owned()),
        };
        let tockb_lockscript = from_cell.lock();

        let data_view =
            ToCKBCellDataView::new(ckb_cell_data.as_ref(), XChainKind::from_int(kind).unwrap())
                .map_err(|err| format!("Parse to ToCKBCellDataView error: {}", err as i8))?;
        let lot_amount = data_view
            .get_lot_xt_amount()
            .map_err(|_| "get lot_amount from tockb cell data error".to_owned())?;
        let from_capacity: u64 = from_cell.capacity().unpack();
        let spv_proof = hex::decode(clear_0x(spv_proof.as_str()))
            .map_err(|err| format!("hex decode spv_proof error: {}", err))?;

        // gen output of tockb cell
        {
            let to_capacity = from_capacity - PLEDGE - XT_CELL_CAPACITY;

            // get tx_id and funding_output_index from spv_proof
            let btc_spv_proof = BTCSPVProof::from_slice(spv_proof.as_slice())
                .map_err(|err| format!("btc_spv_proof invalid: {}", err))?;
            let tx_id = btc_spv_proof.tx_id().raw_data();
            let funding_output_index: u32 = btc_spv_proof.funding_output_index().into();

            let mut output_data_view = data_view.clone();
            output_data_view.status = ToCKBStatus::Warranty;
            output_data_view.x_extra = XExtraView::Btc(BtcExtraView {
                lock_tx_hash: tx_id.into(),
                lock_vout_index: funding_output_index,
            });
            let tockb_data = output_data_view
                .as_molecule_data()
                .expect("output_data_view.as_molecule_data error");
            check_capacity(to_capacity, tockb_data.len())?;

            let to_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(to_capacity).pack())
                .type_(Some(tockb_typescript).pack())
                .lock(tockb_lockscript.clone())
                .build();
            helper.add_output(to_output, tockb_data);
        }

        // 2 xt cells
        {
            // mint xt cell to user, amount = lot_size * (1 - signer fee rate)
            let user_lockscript = Script::from_slice(
                from_ckb_cell_data.user_lockscript().as_slice(),
            )
            .map_err(|e| format!("parse user_lockscript from tockb_cell_data error: {}", e))?;

            let sudt_typescript_code_hash = hex::decode(settings.sudt_script.code_hash)
                .expect("wrong sudt_script code hash config");
            let sudt_typescript = Script::new_builder()
                .code_hash(Byte32::from_slice(&sudt_typescript_code_hash).unwrap())
                .hash_type(DepType::Code.into())
                .args(tockb_lockscript.calc_script_hash().as_bytes().pack())
                .build();

            let sudt_user_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(PLEDGE).pack())
                .type_(Some(sudt_typescript.clone()).pack())
                .lock(user_lockscript)
                .build();

            let (to_user, to_signer) = {
                let signer_fee = lot_amount * SIGNER_FEE_RATE.0 / SIGNER_FEE_RATE.1;
                (lot_amount - signer_fee, signer_fee)
            };

            let to_user_amount_data: Bytes = to_user.to_le_bytes().to_vec().into();
            helper.add_output(sudt_user_output, to_user_amount_data);

            // xt cell of signer fee
            let signer_lockscript = Script::from_slice(
                from_ckb_cell_data.signer_lockscript().as_slice(),
            )
            .map_err(|e| format!("parse signer_lockscript from tockb_cell_data error: {}", e))?;

            let sudt_signer_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(XT_CELL_CAPACITY).pack())
                .type_(Some(sudt_typescript).pack())
                .lock(signer_lockscript)
                .build();

            let to_signer_amount_data = to_signer.to_le_bytes().to_vec().into();
            helper.add_output(sudt_signer_output, to_signer_amount_data);
        }

        // add witness
        {
            let witness_data = MintXTWitness::new_builder()
                .spv_proof(spv_proof.into())
                .cell_dep_index_list(vec![0].into())
                .build();
            let witness = WitnessArgs::new_builder()
                .input_type(Some(witness_data.as_bytes()).pack())
                .build();

            helper.transaction = helper
                .transaction
                .as_advanced_builder()
                .set_witnesses(vec![witness.as_bytes().pack()])
                .build();
        }

        // add signature to pay tx fee
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;

        ToCkbSubCommand::write_ckb_cell_config(cell_path, tx_hash.to_string(), 0)?;
        Ok(tx)
    }

    pub fn pre_term_redeem(
        &mut self,
        args: PreTermRedeemArgs,
        skip_check: bool,
        settings: Settings,
    ) -> Result<TransactionView, String> {
        let PreTermRedeemArgs {
            privkey_path,
            tx_fee,
            cell_path,
            cell,

            x_unlock_address,
            redeemer_lockscript_addr,
        } = args;

        let cell = ToCkbSubCommand::read_ckb_cell_config(cell_path.clone())
            .or(cell.ok_or("cell is none".to_string()))?;
        let tx_fee: u64 = CapacityParser.parse(&tx_fee)?.into();
        let mut helper = TxHelper::default();
        if tx_fee > ONE_CKB {
            return Err("Transaction fee can not be more than 1.0 CKB".to_string());
        }

        // add cellDeps
        {
            let outpoints = vec![
                settings.lockscript.outpoint,
                settings.typescript.outpoint,
                settings.sudt_script.outpoint,
            ];
            self.add_cell_deps(&mut helper, outpoints)?;
        }

        // get input tockb cell and basic info
        let (from_cell, ckb_cell_data) = self.get_ckb_cell(&mut helper, cell, true)?;
        let (tockb_typescript, kind) = match from_cell.type_().to_opt() {
            Some(script) => (script.clone(), script.args().raw_data().as_ref()[0]),
            None => return Err("typescript of tockb cell is none".to_owned()),
        };
        let tockb_lockscript = from_cell.lock();
        let data_view =
            ToCKBCellDataView::new(ckb_cell_data.as_ref(), XChainKind::from_int(kind).unwrap())
                .map_err(|err| format!("Parse to ToCKBCellDataView error: {}", err as i8))?;
        let lot_amount = data_view
            .get_lot_xt_amount()
            .map_err(|_| "get lot_amount from tockb cell data error".to_owned())?;
        let from_capacity: u64 = from_cell.capacity().unpack();

        let sudt_typescript_code_hash = hex::decode(settings.sudt_script.code_hash)
            .expect("wrong sudt_script code hash config");
        let sudt_typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(&sudt_typescript_code_hash).unwrap())
            .hash_type(DepType::Code.into())
            .args(tockb_lockscript.calc_script_hash().as_bytes().pack())
            .build();
        let redeemer_lockscript: Script = Address::from_str(&redeemer_lockscript_addr)?
            .payload()
            .into();

        let (redeemer_is_depositor, user_lockscript) = {
            let from_privkey = PrivkeyPathParser.parse(&privkey_path)?;
            let from_pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &from_privkey);
            let from_address_payload = AddressPayload::from_pubkey(&from_pubkey);
            let redeemer_lockscript = Script::from(&from_address_payload);
            (
                data_view.user_lockscript == redeemer_lockscript.as_bytes(),
                data_view.user_lockscript.clone(),
            )
        };

        // collect xt cell inputs to burn lot_amount xt
        let signer_fee = lot_amount * SIGNER_FEE_RATE.0 / SIGNER_FEE_RATE.1;
        let mut need_sudt_amount = lot_amount;
        if !redeemer_is_depositor {
            need_sudt_amount += signer_fee;
        }

        self.supply_sudt_amount(
            &mut helper,
            need_sudt_amount,
            sudt_typescript.clone(),
            privkey_path.clone(),
            skip_check,
        )?;

        if !redeemer_is_depositor {
            let to_depositor_xt_cell = CellOutput::new_builder()
                .capacity(Capacity::shannons(XT_CELL_CAPACITY).pack())
                .type_(Some(sudt_typescript).pack())
                .lock(
                    Script::from_slice(user_lockscript.as_ref())
                        .expect("user_lockscript decode from input_data error"),
                )
                .build();

            let data = signer_fee.to_le_bytes().to_vec().into();
            helper.add_output(to_depositor_xt_cell, data)
        }

        // gen output of tockb cell
        {
            let to_capacity = from_capacity;
            let mut output_data_view = data_view.clone();
            output_data_view.status = ToCKBStatus::Redeeming;
            output_data_view.x_unlock_address = clear_0x(x_unlock_address.as_str())
                .as_bytes()
                .to_vec()
                .into();
            output_data_view.redeemer_lockscript = redeemer_lockscript.as_bytes();

            let tockb_data = output_data_view
                .as_molecule_data()
                .expect("output_data_view.as_molecule_data error");
            check_capacity(to_capacity, tockb_data.len())?;

            let to_output = CellOutput::new_builder()
                .capacity(Capacity::shannons(to_capacity).pack())
                .type_(Some(tockb_typescript).pack())
                .lock(tockb_lockscript.clone())
                .build();
            helper.add_output(to_output, tockb_data);
        }

        // add signature to pay tx fee
        let tx = self.supply_capacity(&mut helper, tx_fee, privkey_path, skip_check)?;
        let tx_hash = self
            .rpc_client
            .send_transaction(tx.data())
            .map_err(|err| format!("Send transaction error: {}", err))?;
        assert_eq!(tx.hash(), tx_hash.pack());
        self.wait_for_commited(tx_hash.clone(), TIMEOUT)?;

        ToCkbSubCommand::write_ckb_cell_config(cell_path, tx_hash.to_string(), 0)?;
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

    fn get_ckb_cell(
        &mut self,
        helper: &mut TxHelper,
        cell: String,
        add_to_input: bool,
    ) -> Result<(CellOutput, Bytes), String> {
        let parts: Vec<_> = cell.split('.').collect();
        let original_tx_hash: String = parts[0].to_string();
        let original_tx_output_index: u32 = parts[1].parse::<u32>().unwrap();

        let original_tx_outpoint = OutPoint::new_builder()
            .index(original_tx_output_index.pack())
            .tx_hash(Byte32::from_slice(&hex::decode(original_tx_hash).unwrap()).unwrap())
            .build();

        if add_to_input {
            let genesis_info = self.genesis_info()?;

            let mut get_live_cell_fn = |out_point: OutPoint, with_data: bool| {
                get_live_cell(self.rpc_client, out_point, with_data).map(|(output, _)| output)
            };

            helper.add_input(
                original_tx_outpoint.clone(),
                None,
                &mut get_live_cell_fn,
                &genesis_info,
                true,
            )?;
        }

        get_live_cell(self.rpc_client, original_tx_outpoint, true)
    }

    fn read_ckb_cell_config(cell_path: String) -> Result<String, String> {
        let ckb_cell = CKBCell::new(&cell_path)
            .map_err(|e| format!("failed to load ckb cell from {}, err: {}", &cell_path, e))?;
        let cell = ckb_cell.outpoint.tx_hash + "." + &ckb_cell.outpoint.index.to_string();
        Ok(cell.to_string())
    }

    fn write_ckb_cell_config(cell_path: String, tx_hash: String, index: u32) -> Result<(), String> {
        let mut ckb_cell = CKBCell::default();
        ckb_cell.outpoint = OutpointConf { tx_hash, index };
        let s = toml::to_string(&ckb_cell).expect("toml serde error");
        println!("ckb cell: \n\n{}", &s);
        ckb_cell.write(&cell_path)
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
            ("dev-set-btc-difficulty-cell", Some(m)) => {
                let args = SetBtcDifficultArgs {
                    config_path,
                    privkey_path: get_arg_value(m, "privkey-path")?,
                    skip_check: false,
                    difficulty: get_arg_value(m, "difficulty")?
                        .parse()
                        .map_err(|e| format!("parse difficulty error: {}", e))?,
                };
                self.set_btc_difficulty_cell(args)
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
                    cell_path: get_arg_value(m, "cell-path").map(|s| s.to_string())?,
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
                    cell: m.value_of("cell").map(|s| s.to_string()),
                    cell_path: get_arg_value(m, "cell-path").map(|s| s.to_string())?,
                    lock_address: get_arg_value(m, "lock-address").map(|s| s.to_string())?,
                    signer_lockscript_addr: get_arg_value(m, "signer-lockscript-addr")
                        .map(|s| s.to_string())?,
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
            ("mint_xt", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = MintXtArgs {
                    cell: m.value_of("cell").map(|s| s.to_string()),
                    cell_path: get_arg_value(m, "cell-path").map(|s| s.to_string())?,
                    spv_proof: get_arg_value(m, "spv-proof")?
                        .parse()
                        .map_err(|_e| "parse spv_proof error".to_owned())?,
                    privkey_path: get_arg_value(m, "privkey-path").map(|s| s.to_string())?,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                };
                let tx = self.mint_xt(args, true, settings)?;
                if debug {
                    let rpc_tx_view = json_types::TransactionView::from(tx);
                    Ok(Output::new_output(rpc_tx_view))
                } else {
                    let tx_hash: H256 = tx.hash().unpack();
                    Ok(Output::new_output(tx_hash))
                }
            }
            ("pre-term_redeem", Some(m)) => {
                let settings = Settings::new(&config_path).map_err(|e| {
                    format!("failed to load config from {}, err: {}", &config_path, e)
                })?;
                let args = PreTermRedeemArgs {
                    cell: m.value_of("cell").map(|s| s.to_string()),
                    cell_path: get_arg_value(m, "cell-path").map(|s| s.to_string())?,
                    privkey_path: get_arg_value(m, "privkey-path").map(|s| s.to_string())?,
                    tx_fee: get_arg_value(m, "tx-fee")?,
                    x_unlock_address: get_arg_value(m, "unlock-address").map(|s| s.to_string())?,
                    redeemer_lockscript_addr: get_arg_value(m, "redeemer-lockscript-addr")
                        .map(|s| s.to_string())?,
                };
                let tx = self.pre_term_redeem(args, true, settings)?;
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

pub fn clear_0x(s: &str) -> &str {
    if &s[..2] == "0x" || &s[..2] == "0X" {
        &s[2..]
    } else {
        s
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
pub struct SetBtcDifficultArgs {
    pub privkey_path: String,
    pub config_path: String,
    pub skip_check: bool,
    pub difficulty: u64,
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

    pub cell_path: String,
}

#[derive(Clone, Debug)]
pub struct BondingArgs {
    pub privkey_path: String,
    pub tx_fee: String,

    pub cell_path: String,
    pub cell: Option<String>,

    pub lock_address: String,
    pub signer_lockscript_addr: String,
}

#[derive(Clone, Debug)]
pub struct MintXtArgs {
    pub privkey_path: String,
    pub tx_fee: String,

    pub cell_path: String,
    pub cell: Option<String>,

    pub spv_proof: String,
}

#[derive(Clone, Debug)]
pub struct PreTermRedeemArgs {
    pub privkey_path: String,
    pub tx_fee: String,

    pub cell_path: String,
    pub cell: Option<String>,

    pub x_unlock_address: String,
    pub redeemer_lockscript_addr: String,
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

#[test]
fn test_cmd() {}
