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
    pub fn new(client: Client, address_str: &str, contract_json: &str) -> Self {
        let address = Address::from_str(remove_0x(address_str)).unwrap();
        let contract = Contract::load(contract_json.as_bytes()).unwrap();
        ContractClient {
            client,
            address,
            contract,
        }
    }

    /// Create a Group Management contract client
    pub fn group_management(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/GroupManagement.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241C2";
        let client = client.unwrap_or_else(|| Client::new().unwrap());
        Self::new(client, ADDRESS, ABI)
    }

    /// Create a Node Management contract client
    pub fn node_management(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/NodeManager.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241a2";
        let client = client.unwrap_or_else(|| Client::new().unwrap());
        Self::new(client, ADDRESS, ABI)
    }

    /// Create a Quota Management contract client
    pub fn quota_management(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/QuotaManager.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241a3";
        let client = client.unwrap_or_else(|| Client::new().unwrap());
        Self::new(client, ADDRESS, ABI)
    }

    /// Call/SendTx a contract method
    pub fn contract_call(
        &mut self,
        url: &str,
        name: &str,
        values: &[&str],
        blake2b: Option<bool>,
    ) -> Result<JsonRpcResponse, ToolError> {
        let values = values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let code = contract_encode_input(&self.contract, name, values.as_slice(), true)?;
        let code = format!("0x{}", code);
        let to_address = format!("{:?}", self.address);
        if let Some(blake2b) = blake2b {
            self.client.send_raw_transaction(
                url,
                code.as_str(),
                to_address.as_str(),
                None,
                None,
                None,
                blake2b,
            )
        } else {
            self.client.call(
                url,
                None,
                to_address.as_str(),
                Some(code.as_str()),
                "latest",
            )
        }
    }
}

/// GroupManagement System Contract
pub trait GroupManagementExt {
    /// Rpc response
    type RpcResult;

    /// Create a new group
    fn new_group(
        &mut self,
        url: &str,
        origin: &str,
        name: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Delete the group
    fn delete_group(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Update the group name
    fn update_group_name(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        name: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Add accounts
    fn add_accounts(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Delete accounts
    fn delete_accounts(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        accounts: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Check the target group in the scope of the origin group
    ///   Scope: the origin group is the ancestor of the target group
    fn check_scope(&mut self, url: &str, origin: &str, target: &str) -> Self::RpcResult;

    /// Query all groups
    fn query_groups(&mut self, url: &str) -> Self::RpcResult;
}

impl GroupManagementExt for ContractClient {
    type RpcResult = Result<JsonRpcResponse, ToolError>;
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
        self.contract_call(url, "newGroup", values.as_slice(), Some(blake2b))
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
        self.contract_call(url, "deleteGroup", values.as_slice(), Some(blake2b))
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
        self.contract_call(url, "updateGroupName", values.as_slice(), Some(blake2b))
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
        self.contract_call(url, "addAccounts", values.as_slice(), Some(blake2b))
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
        self.contract_call(url, "deleteAccounts", values.as_slice(), Some(blake2b))
    }

    /// Check the target group in the scope of the origin group
    ///   Scope: the origin group is the ancestor of the target group
    fn check_scope(&mut self, url: &str, origin: &str, target: &str) -> Self::RpcResult {
        let values = vec![origin, target];
        self.contract_call(url, "checkScope", values.as_slice(), None)
    }

    /// Query all groups
    fn query_groups(&mut self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "queryGroups", vec![].as_slice(), None)
    }
}

/// NodeManager system contract
pub trait NodeManagementExt {
    /// Rpc response
    type RpcResult;

    /// Downgrade consensus node to ordinary node
    fn downgrade_consensus_node(
        &mut self,
        url: &str,
        address: &str,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Get node status
    fn node_status(&mut self, url: &str, address: &str) -> Self::RpcResult;

    /// Get authorities
    fn get_authorities(&mut self, url: &str) -> Result<Vec<String>, ToolError>;

    /// Applying to promote nodes as consensus nodes
    fn new_consensus_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult;

    /// Approve node upgrades to consensus nodes
    fn approve_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult;
}

impl NodeManagementExt for ContractClient {
    type RpcResult = Result<JsonRpcResponse, ToolError>;

    fn downgrade_consensus_node(
        &mut self,
        url: &str,
        address: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = vec![address];
        self.contract_call(url, "deleteNode", values.as_slice(), Some(blake2b))
    }

    fn node_status(&mut self, url: &str, address: &str) -> Self::RpcResult {
        let values = vec![address];
        self.contract_call(url, "getStatus", values.as_slice(), None)
    }

    fn get_authorities(&mut self, url: &str) -> Result<Vec<String>, ToolError> {
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

    fn new_consensus_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![address];
        self.contract_call(url, "newNode", value.as_slice(), Some(blake2b))
    }

    fn approve_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![address];
        self.contract_call(url, "approveNode", value.as_slice(), Some(blake2b))
    }
}

/// QuotaManager system contract
pub trait QuotaManagementExt {
    /// Rpc response
    type RpcResult;

    /// Get block quota upper limit
    fn get_bql(&mut self, url: &str) -> Self::RpcResult;

    /// Get account quota upper limit of the specific account
    fn get_aql(&mut self, url: &str, address: &str) -> Self::RpcResult;

    /// Get default account quota limit
    fn get_default_aql(&mut self, url: &str) -> Self::RpcResult;

    /// Get accounts
    fn get_accounts(&mut self, url: &str) -> Self::RpcResult;

    /// Get quotas
    fn get_quotas(&mut self, url: &str) -> Self::RpcResult;

    /// Set block quota limit
    fn set_bql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult;

    /// Set default account quota limit
    fn set_default_aql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult;

    /// Set account quota upper limit of the specific account
    fn set_aql(
        &mut self,
        url: &str,
        address: &str,
        quota_limit: u64,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Check if the account is admin
    fn is_admin(&mut self, url: &str, address: &str) -> Self::RpcResult;

    /// Add admin account
    fn add_admin(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult;
}

impl QuotaManagementExt for ContractClient {
    type RpcResult = Result<JsonRpcResponse, ToolError>;

    fn get_bql(&mut self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getBQL", &[], None)
    }

    fn get_aql(&mut self, url: &str, address: &str) -> Self::RpcResult {
        let value = vec![address];
        self.contract_call(url, "getAQL", value.as_slice(), None)
    }

    fn get_default_aql(&mut self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getDefaultAQL", &[], None)
    }

    fn get_accounts(&mut self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getAccounts", &[], None)
    }

    fn get_quotas(&mut self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "getQuotas", &[], None)
    }

    fn set_bql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![quota_limit.as_str()];
        self.contract_call(url, "setBQL", value.as_slice(), Some(blake2b))
    }

    fn set_default_aql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![quota_limit.as_str()];
        self.contract_call(url, "setDefaultAQL", value.as_slice(), Some(blake2b))
    }

    fn set_aql(
        &mut self,
        url: &str,
        address: &str,
        quota_limit: u64,
        blake2b: bool,
    ) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let value = vec![address, quota_limit.as_str()];
        self.contract_call(url, "setAQL", value.as_slice(), Some(blake2b))
    }

    fn is_admin(&mut self, url: &str, address: &str) -> Self::RpcResult {
        let value = vec![address];
        self.contract_call(url, "isAdmin", value.as_slice(), None)
    }

    fn add_admin(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let value = vec![address];
        self.contract_call(url, "addAdmin", value.as_slice(), Some(blake2b))
    }
}
