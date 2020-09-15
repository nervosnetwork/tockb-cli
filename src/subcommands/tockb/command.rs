use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, DepType, Capacity, ScriptHashType, TransactionView},
    h256,
    packed::{self, CellDep, Byte32, CellOutput, OutPoint, Script},
    prelude::*,
    H160, H256,
};
use int_enum::IntEnum;
use clap::{App, AppSettings, Arg, ArgMatches};
use serde::{Deserialize, Serialize};
use tockb_types::{tockb_cell, config, generated::{basic, tockb_cell_data::ToCKBCellData}};
use molecule::prelude::Byte;

use super::consts::{TOCKB_TYPESCRIPT_HASH, TOCKB_LOCKSCRIPT_HASH};
use crate::subcommands::{CliSubCommand, Output};
use crate::plugin::{KeyStoreHandler, PluginManager, SignTarget};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, FromStrParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    index::IndexController,
    other::{
        check_capacity, get_address, get_arg_value, get_live_cell_with_cache,
        get_max_mature_number, get_network_type, get_privkey_signer, get_to_data, is_mature,
        read_password, sync_to_tip,
    },
};
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_sdk::{
    constants::{
        DAO_TYPE_HASH, MIN_SECP_CELL_CAPACITY, MULTISIG_TYPE_HASH, ONE_CKB, SIGHASH_TYPE_HASH,
    },
    wallet::DerivationPath,
    Address, AddressPayload, GenesisInfo, HttpRpcClient, HumanCapacity, MultisigConfig, SignerFn,
    Since, SinceType, TxHelper, SECP256K1,
};
pub use crate::subcommands::wallet::start_index_thread;

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
            .subcommands(vec![
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

    pub fn deposit_request(
        &mut self,
        args: DepositRequestArgs,
        skip_check: bool,
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
        // let to_capacity: u64 = CapacityParser.parse(&capacity)?.into();
        // let to_capacity: u64 = pledge.parse().map_err(|_e| "parse pledge error".to_owned())?;
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
            .tx_hash(Byte32::from_slice(&hex::decode("24530a24a5711c2e017631b3afc4adf25e55d9af31b22eff7e455f65642a4c09").unwrap()).unwrap())
            .index(0u32.pack())
            .build();
        let typescript_out_point = OutPoint::new_builder()
            .tx_hash(Byte32::from_slice(&hex::decode("786e51c239122e96b1e44496f8c30012d0f7099917e69dd938523b125a46e354").unwrap()).unwrap())
            .index(0u32.pack())
            .build();
        let typescript_cell_dep = CellDep::new_builder()
            .out_point(typescript_out_point)
            .dep_type(DepType::Code.into())
            .build();
        let lockscript_cell_dep = CellDep::new_builder()
            .out_point(lockscript_out_point)
            .dep_type(DepType::Code.into())
            .build();
        helper.transaction = helper.transaction.as_advanced_builder()
            .cell_dep(typescript_cell_dep)
            .cell_dep(lockscript_cell_dep)
            .build();
        let toCKB_data = ToCKBCellData::new_builder()
            .status(Byte::new(tockb_cell::ToCKBStatus::Initial.int_value()))
            .lot_size(Byte::new(lot_size))
            .build().as_bytes();
        check_capacity(to_capacity, toCKB_data.len())?;
        let typescript = Script::new_builder()
            .code_hash(Byte32::from_slice(TOCKB_TYPESCRIPT_HASH.as_ref()).unwrap())
            .hash_type(DepType::Code.into())
            .args(vec![kind].pack())
            .build();
        let lockscript = Script::new_builder()
            .code_hash(Byte32::from_slice(TOCKB_LOCKSCRIPT_HASH.as_ref()).unwrap())
            .hash_type(DepType::Code.into())
            .args(TOCKB_TYPESCRIPT_HASH.as_ref().pack())
            .build();
        let to_output = CellOutput::new_builder()
            .capacity(Capacity::shannons(to_capacity).pack())
            .type_(Some(typescript).pack())
            .lock(lockscript)
            .build();
        helper.add_output(to_output, toCKB_data);
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

    pub fn get_capacity(&mut self, lock_hashes: Vec<Byte32>) -> Result<(u64, u64, u64), String> {
        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        self.with_db(|db| {
            let mut total_capacity = 0;
            let mut dao_capacity = 0;
            let mut immature_capacity = 0;
            let mut terminator = |_idx: usize, info: &LiveCellInfo| {
                if !is_mature(info, max_mature_number) {
                    immature_capacity += info.capacity;
                }
                if info
                    .type_hashes
                    .as_ref()
                    .filter(|(code_hash, _)| code_hash == &DAO_TYPE_HASH)
                    .is_some()
                {
                    dao_capacity += info.capacity;
                }
                total_capacity += info.capacity;
                (false, false)
            };
            for lock_hash in lock_hashes {
                let _ = db.get_live_cells_by_lock(lock_hash, None, &mut terminator);
            }
            (total_capacity, immature_capacity, dao_capacity)
        })
    }

    pub fn get_live_cells<F>(
        &mut self,
        to_number: u64,
        limit: usize,
        mut func: F,
        fast_mode: bool,
    ) -> Result<(LiveCells, Option<(u32, u64)>), String>
        where
            F: FnMut(
                &IndexDatabase,
                &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
            ) -> Vec<LiveCellInfo>,
    {
        let (infos, total_count, total_capacity, current_count, current_capacity) =
            self.with_db(|db| {
                let mut total_count: u32 = 0;
                let mut total_capacity: u64 = 0;
                let mut current_count: u32 = 0;
                let mut current_capacity: u64 = 0;
                let mut terminator = |idx, info: &LiveCellInfo| {
                    let stop = idx >= limit || info.number > to_number;
                    let push_info = !stop;
                    total_count += 1;
                    total_capacity += info.capacity;
                    if push_info {
                        current_count += 1;
                        current_capacity += info.capacity;
                    }
                    (fast_mode && stop, push_info)
                };
                let infos = func(&db, &mut terminator);
                (
                    infos,
                    total_count,
                    total_capacity,
                    current_count,
                    current_capacity,
                )
            })?;

        let max_mature_number = get_max_mature_number(self.rpc_client)?;
        let live_cells = infos
            .into_iter()
            .map(|info| {
                let mature = is_mature(&info, max_mature_number);
                LiveCell { info, mature }
            })
            .collect::<Vec<_>>();
        let total = if fast_mode {
            None
        } else {
            Some((total_count, total_capacity))
        };
        Ok((
            LiveCells {
                live_cells,
                current_count,
                current_capacity,
            },
            total,
        ))
    }
}

impl<'a> CliSubCommand for ToCkbSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("deposit_request", Some(m)) => {
                let to_data = get_to_data(m)?;
                let args = DepositRequestArgs {
                    pledge: get_arg_value(m,"pledge")?.parse().map_err(|_e| "parse pledge error".to_owned())?,
                    kind: get_arg_value(m,"kind")?.parse().map_err(|_e| "parse kind error".to_owned())?,
                    lot_size: get_arg_value(m,"lot_size")?.parse().map_err(|_e| "parse lot_size error".to_owned())?,
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
                let tx = self.deposit_request(args, false)?;
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
