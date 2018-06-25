use client::basic::{Client, ClientExt};
use client::remove_0x;

use std::str::{self, FromStr};

use abi::contract_encode_input;
use error::ToolError;
use ethabi::{Address, Contract};
use rpctypes::{JsonRpcResponse, ParamsValue, ResponseValue};

/// Contract Client
pub struct ContractClient {
    client: Client,
    address: Address,
    contract: Contract,
}

impl ContractClient {
    /// Create a Contract Client
    pub fn new(client: Option<Client>, address_str: &str, contract_json: &str) -> Self {
        let client = client.unwrap_or_else(|| Client::new().unwrap());
        let address = Address::from_str(remove_0x(address_str)).unwrap();
        let contract = Contract::load(contract_json.as_bytes()).unwrap();
        ContractClient {
            client,
            address,
            contract,
        }
    }
}

/// Call/SendTx to a contract method
pub trait ContractCall {
    /// Rpc response
    type RpcResult;

    /// Prepare contract call arguments
    fn prepare_call_args(
        &self,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
    ) -> Result<(String, String), ToolError>;

    /// SendTx a contract method
    fn contract_send_tx(
        &mut self,
        url: &str,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Call a contract method
    fn contract_call(
        &self,
        url: &str,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
    ) -> Self::RpcResult;
}

impl ContractCall for ContractClient {
    type RpcResult = Result<JsonRpcResponse, ToolError>;

    fn prepare_call_args(
        &self,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
    ) -> Result<(String, String), ToolError> {
        let values = values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let code = contract_encode_input(&self.contract, name, values.as_slice(), true)?;
        let code = format!("0x{}", code);
        let to_address = to_addr.unwrap_or(self.address);
        let to_address = format!("{:?}", to_address);
        Ok((code, to_address))
    }

    fn contract_send_tx(
        &mut self,
        url: &str,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let (code, to_address) = self.prepare_call_args(name, values, to_addr)?;
        self.client.send_raw_transaction(
            url,
            code.as_str(),
            to_address.as_str(),
            None,
            None,
            None,
            blake2b,
        )
    }

    fn contract_call(
        &self,
        url: &str,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
    ) -> Self::RpcResult {
        let (code, to_address) = self.prepare_call_args(name, values, to_addr)?;
        self.client.call(
            url,
            None,
            to_address.as_str(),
            Some(code.as_str()),
            "latest",
        )
    }
}

/// Group System Contract
pub trait GroupExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Call a group query function
    fn group_query(
        &self,
        url: &str,
        function_name: &str,
        values: &[&str],
        address: &str,
    ) -> Self::RpcResult {
        let address = Address::from_str(remove_0x(address)).unwrap();
        self.contract_call(url, function_name, values, Some(address))
    }
    /// Query the information of the group
    fn query_info(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryInfo", &[], address)
    }
    /// Query the name of the group
    fn query_name(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryName", &[], address)
    }
    /// Query the accounts of the group
    fn query_accounts(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryAccounts", &[], address)
    }
    /// Query the child of the group
    fn query_children(&self, url: &str, address: &str) -> Self::RpcResult {
        self.query_child(url, address)
    }
    /// Alias for group_query_children
    fn query_child(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryChild", &[], address)
    }
    /// Query the length of children of the group
    fn query_children_length(&self, url: &str, address: &str) -> Self::RpcResult {
        self.query_child_length(url, address)
    }
    /// Alias for group_query_children_length
    fn query_child_length(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryChildLength", &[], address)
    }
    /// Query the parent of the group
    fn query_parent(&self, url: &str, address: &str) -> Self::RpcResult {
        self.group_query(url, "queryParent", &[], address)
    }
    /// Check the account in the group
    fn in_group(&self, url: &str, address: &str, account_address: &str) -> Self::RpcResult {
        self.group_query(url, "inGroup", &[account_address], address)
    }
}

impl GroupExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/Group.abi");
        // NOTE: This is `rootGroupAddr` address
        static ADDRESS: &str = "0x00000000000000000000000000000000013241b6";
        Self::new(client, ADDRESS, ABI)
    }
}

/// GroupManagement System Contract
pub trait GroupManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Create a new group
    fn new_group(
        &mut self,
        url: &str,
        origin: &str,
        name: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![origin, name, accounts];
        self.contract_send_tx(url, "newGroup", values.as_slice(), None, blake2b)
    }

    /// Delete the group
    fn delete_group(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![origin, target];
        self.contract_send_tx(url, "deleteGroup", values.as_slice(), None, blake2b)
    }

    /// Update the group name
    fn update_group_name(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        name: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![origin, target, name];
        self.contract_send_tx(url, "updateGroupName", values.as_slice(), None, blake2b)
    }

    /// Add accounts
    fn add_accounts(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![origin, target, accounts];
        self.contract_send_tx(url, "addAccounts", values.as_slice(), None, blake2b)
    }

    /// Delete accounts
    fn delete_accounts(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![origin, target, accounts];
        self.contract_send_tx(url, "deleteAccounts", values.as_slice(), None, blake2b)
    }

    /// Check the target group in the scope of the origin group
    ///   Scope: the origin group is the ancestor of the target group
    fn check_scope(&self, url: &str, origin: &str, target: &str) -> Self::RpcResult {
        let values = vec![origin, target];
        self.contract_call(url, "checkScope", values.as_slice(), None)
    }

    /// Query all groups
    fn query_groups(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "queryGroups", vec![].as_slice(), None)
    }
}

impl GroupManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/GroupManagement.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241C2";
        Self::new(client, ADDRESS, ABI)
    }
}

/// NodeManager system contract
pub trait NodeManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Downgrade consensus node to ordinary node
    fn downgrade_consensus_node(
        &mut self,
        url: &str,
        address: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![remove_0x(address)];
        self.contract_send_tx(url, "deleteNode", values.as_slice(), None, blake2b)
    }

    /// Get node status
    fn node_status(&self, url: &str, address: &str) -> Self::RpcResult {
        let values = vec![remove_0x(address)];
        self.contract_call(url, "getStatus", values.as_slice(), None)
    }

    /// Get authorities
    fn get_authorities(&self, url: &str) -> Result<Vec<String>, ToolError>;

    /// Applying to promote nodes as consensus nodes
    fn new_consensus_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![remove_0x(address)];
        self.contract_send_tx(url, "newNode", value.as_slice(), None, blake2b)
    }

    /// Approve node upgrades to consensus nodes
    fn approve_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![remove_0x(address)];
        self.contract_send_tx(url, "approveNode", value.as_slice(), None, blake2b)
    }
}

impl NodeManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/NodeManager.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241a2";
        Self::new(client, ADDRESS, ABI)
    }

    fn get_authorities(&self, url: &str) -> Result<Vec<String>, ToolError> {
        if let Some(ResponseValue::Singe(ParamsValue::String(authorities))) =
            self.contract_call(url, "listNode", &[], None)?.result()
        {
            Ok(remove_0x(&authorities)
                .as_bytes()
                .chunks(64)
                .skip(2)
                .map(|data| format!("0x{}", str::from_utf8(&data[24..]).unwrap()))
                .collect::<Vec<String>>())
        } else {
            Ok(Vec::new())
        }
    }
}

/// QuotaManager system contract
pub trait QuotaManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Get block quota upper limit
    fn get_bql(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getBQL", &[], None)
    }

    /// Get account quota upper limit of the specific account
    fn get_aql(&self, url: &str, address: &str) -> Self::RpcResult {
        let value = vec![remove_0x(address)];
        self.contract_call(url, "getAQL", value.as_slice(), None)
    }

    /// Get default account quota limit
    fn get_default_aql(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getDefaultAQL", &[], None)
    }

    /// Get accounts
    fn get_accounts(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getAccounts", &[], None)
    }

    /// Get quotas
    fn get_quotas(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getQuotas", &[], None)
    }

    /// Set block quota limit
    fn set_bql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![quota_limit.as_str()];
        self.contract_send_tx(url, "setBQL", value.as_slice(), None, blake2b)
    }

    /// Set default account quota limit
    fn set_default_aql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![quota_limit.as_str()];
        self.contract_send_tx(url, "setDefaultAQL", value.as_slice(), None, blake2b)
    }

    /// Set account quota upper limit of the specific account
    fn set_aql(
        &mut self,
        url: &str,
        address: &str,
        quota_limit: u64,
        blake2b: bool,
    ) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![remove_0x(address), quota_limit.as_str()];
        self.contract_send_tx(url, "setAQL", value.as_slice(), None, blake2b)
    }

    /// Check if the account is admin
    fn is_admin(&self, url: &str, address: &str) -> Self::RpcResult {
        let value = vec![remove_0x(address)];
        self.contract_call(url, "isAdmin", value.as_slice(), None)
    }

    /// Add admin account
    fn add_admin(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![remove_0x(address)];
        self.contract_send_tx(url, "addAdmin", value.as_slice(), None, blake2b)
    }
}

impl QuotaManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/QuotaManager.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241a3";
        Self::new(client, ADDRESS, ABI)
    }
}
