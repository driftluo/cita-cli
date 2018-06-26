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

    /// Call a contract method with a to_address
    fn contract_call_to_address(
        &self,
        url: &str,
        function_name: &str,
        values: &[&str],
        address: &str,
    ) -> Self::RpcResult {
        let address = Address::from_str(remove_0x(address)).unwrap();
        self.contract_call(url, function_name, values, Some(address))
    }
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

    /// Query the information of the group
    fn query_info(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryInfo", &[], address)
    }
    /// Query the name of the group
    fn query_name(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryName", &[], address)
    }
    /// Query the accounts of the group
    fn query_accounts(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryAccounts", &[], address)
    }
    /// Alias for query_child
    fn query_children(&self, url: &str, address: &str) -> Self::RpcResult {
        self.query_child(url, address)
    }
    /// Query the children of the group
    fn query_child(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryChild", &[], address)
    }
    /// Alias for query_child_length
    fn query_children_length(&self, url: &str, address: &str) -> Self::RpcResult {
        self.query_child_length(url, address)
    }
    /// Query the length of children of the group
    fn query_child_length(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryChildLength", &[], address)
    }
    /// Query the parent of the group
    fn query_parent(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryParent", &[], address)
    }
    /// Check the account in the group
    fn in_group(&self, url: &str, address: &str, account_address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "inGroup", &[account_address], address)
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
        let values = [remove_0x(origin), name, accounts];
        self.contract_send_tx(url, "newGroup", &values, None, blake2b)
    }

    /// Delete the group
    fn delete_group(
        &mut self,
        url: &str,
        origin: &str,
        target: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target)];
        self.contract_send_tx(url, "deleteGroup", &values, None, blake2b)
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
        let values = [remove_0x(origin), remove_0x(target), name];
        self.contract_send_tx(url, "updateGroupName", &values, None, blake2b)
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
        let values = [remove_0x(origin), remove_0x(target), accounts];
        self.contract_send_tx(url, "addAccounts", &values, None, blake2b)
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
        let values = [remove_0x(origin), remove_0x(target), accounts];
        self.contract_send_tx(url, "deleteAccounts", &values, None, blake2b)
    }

    /// Check the target group in the scope of the origin group
    ///   Scope: the origin group is the ancestor of the target group
    fn check_scope(&self, url: &str, origin: &str, target: &str) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target)];
        self.contract_call(url, "checkScope", &values, None)
    }

    /// Query all groups
    fn query_groups(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "queryGroups", &[], None)
    }
}

impl GroupManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/GroupManagement.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241C2";
        Self::new(client, ADDRESS, ABI)
    }
}

/// Role system contract
pub trait RoleExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Query the information of the role
    ///
    /// return The information of role: name and permissions
    fn query_role(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryRole", &[], address)
    }

    /// Query the name of the role
    ///
    /// return The name of role
    fn query_name(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryName", &[], address)
    }

    /// Query the permissions of the role
    ///
    /// return The permissions of role
    fn query_permissions(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryPermissions", &[], address)
    }

    /// Query the length of the permissions
    ///
    /// return The number of permission
    fn length_of_permissions(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "lengthOfPermissions", &[], address)
    }

    /// Check the duplicate permission
    ///
    /// return true if in permissions, otherwise false
    fn in_permissions(&self, url: &str, address: &str, permission: &str) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_call_to_address(url, "inPermissions", &values, address)
    }
}

impl RoleExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/Role.abi");
        // NOTE: There is no default address for Role
        static ADDRESS: &str = "0x";
        Self::new(client, ADDRESS, ABI)
    }
}

/// RoleManagement system contract
pub trait RoleManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Create a new role
    ///
    /// param name: The name of role
    /// param permissions: The permissions of role
    /// return New role's address
    fn new_role(
        &mut self,
        url: &str,
        name: &str,
        permissions: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [name, permissions];
        self.contract_send_tx(url, "newRole", &values, None, blake2b)
    }

    /// Delete the role
    ///
    /// param role: The address of role
    /// return true if successed, otherwise false
    fn delete_role(&mut self, url: &str, role: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(role)];
        self.contract_send_tx(url, "deleteRole", &values, None, blake2b)
    }

    /// Update role's name
    ///
    /// param role: The address of role
    /// param name: The new name of role
    /// return true if successed, otherwise false
    fn update_role_name(
        &mut self,
        url: &str,
        role: &str,
        name: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), name];
        self.contract_send_tx(url, "updateRoleName", &values, None, blake2b)
    }

    /// Add permissions of role
    ///
    /// param role: The address of role
    /// param permissions: The permissions of role
    /// return true if successed, otherwise false
    fn add_permissions(
        &mut self,
        url: &str,
        role: &str,
        permissions: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), permissions];
        self.contract_send_tx(url, "addPermissions", &values, None, blake2b)
    }

    /// Delete permissions of role
    ///
    /// param role: The address of role
    /// param permissions: The permissions of role
    /// return true if successed, otherwise false
    fn delete_permissions(
        &mut self,
        url: &str,
        role: &str,
        permissions: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), permissions];
        self.contract_send_tx(url, "deletePermissions", &values, None, blake2b)
    }

    /// Set the role to the account
    ///
    /// param account: The account to be setted
    /// param role: The role to be setted
    /// return true if successed, otherwise false
    fn set_role(&mut self, url: &str, account: &str, role: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(role)];
        self.contract_send_tx(url, "setRole", &values, None, blake2b)
    }

    /// Cancel the account's role
    ///
    /// param account: The account to be canceled
    /// param role: The role to be canceled
    /// return true if successed, otherwise false
    fn cancel_role(
        &mut self,
        url: &str,
        account: &str,
        role: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(role)];
        self.contract_send_tx(url, "cancelRole", &values, None, blake2b)
    }

    /// Clear the account's role
    ///
    /// param account: The account to be cleared
    /// return true if successed, otherwise false
    fn clear_role(&mut self, url: &str, account: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_send_tx(url, "clearRole", &values, None, blake2b)
    }

    /// Query the roles of the account
    ///
    /// param account: The account to be queried
    /// return The roles of the account
    fn query_roles(&self, url: &str, account: &str) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_call(url, "queryRoles", &values, None)
    }

    /// Query the accounts that have the role
    ///
    /// param role: The role to be queried
    /// return The accounts that have the role
    fn query_accounts(&self, url: &str, role: &str) -> Self::RpcResult {
        let values = [remove_0x(role)];
        self.contract_call(url, "queryAccounts", &values, None)
    }
}

impl RoleManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/RoleManagement.abi");
        static ADDRESS: &str = "0xe3b5ddb80addb513b5c981e27bb030a86a8821ee";
        Self::new(client, ADDRESS, ABI)
    }
}

/// Authorization system contract
pub trait AuthorizationExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Query the account's permissions
    ///
    /// param account: The account to be queried
    /// return The permissions of account
    fn query_permissions(&self, url: &str, account: &str) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_call(url, "queryPermissions", &values, None)
    }

    /// Query the permission's accounts
    ///
    /// param permission: The permission to be queried
    /// return The accounts of permission
    fn query_accounts(&self, url: &str, permission: &str) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_call(url, "queryAccounts", &values, None)
    }

    /// Query all accounts
    ///
    /// return All the accounts
    fn query_all_accounts(&self, url: &str) -> Self::RpcResult {
        self.contract_call(url, "queryAllAccounts", &[], None)
    }

    /// Check Permission
    ///
    /// param account: The account to be checked
    /// param contract: The contract of resource
    /// param func: The function signature of resource
    /// return true if passed, otherwise false
    fn check_permission(
        &self,
        url: &str,
        account: &str,
        countract: &str,
        func: &str,
    ) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(countract), remove_0x(func)];
        self.contract_call(url, "checkPermission", &values, None)
    }
}

impl AuthorizationExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/Authorization.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241b4";
        Self::new(client, ADDRESS, ABI)
    }
}

/// Permission system contract
pub trait PermissionExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Check resource in the permission
    ///
    /// param contract: The contract address of the resource
    /// param func: The function signature of the resource
    /// return true if in permission, otherwise false
    fn in_permission(
        &self,
        url: &str,
        address: &str,
        contract: &str,
        func: &str,
    ) -> Self::RpcResult {
        let values = [remove_0x(contract), remove_0x(func)];
        self.contract_call_to_address(url, "inPermission", &values, address)
    }

    /// Query the information of the permission
    ///
    /// return The information of permission: name and resources
    fn query_info(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryInfo", &[], address)
    }

    /// Query the name of the permission
    ///
    /// return The name of permission
    fn query_name(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryName", &[], address)
    }

    /// Query the resource of the permission
    ///
    /// return The resources of permission
    fn query_resource(&self, url: &str, address: &str) -> Self::RpcResult {
        self.contract_call_to_address(url, "queryResource", &[], address)
    }
}

impl PermissionExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/Permission.abi");
        // NOTE: There is no default address for Permission
        static ADDRESS: &str = "0x";
        Self::new(client, ADDRESS, ABI)
    }
}

/// PermissionManagement system contract
pub trait PermissionManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Create a new permission
    ///
    /// param name: The name of permission
    /// param contracts: The contracts of resource
    /// param funcs: The function signature of the resource
    /// return New permission's address
    fn new_permission(
        &mut self,
        url: &str,
        name: &str,
        contracts: &str,
        funcs: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [name, contracts, funcs];
        self.contract_send_tx(url, "newPermission", &values, None, blake2b)
    }

    /// Delete the permission
    ///
    /// param permission: The address of permission
    /// return true if successed, otherwise false
    fn delete_permission(&mut self, url: &str, permission: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_send_tx(url, "deletePermission", &values, None, blake2b)
    }

    /// Update the permission name
    ///
    /// param permission: The address of permission
    /// param name: The new name
    /// return true if successed, otherwise false
    fn update_permission_name(
        &mut self,
        url: &str,
        permission: &str,
        name: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), name];
        self.contract_send_tx(url, "updatePermissionName", &values, None, blake2b)
    }

    /// Add the resources of permission
    ///
    /// param permission: The address of permission
    /// param contracts: The contracts of resource
    /// param funcs: The function signature of resource
    /// return true if successed, otherwise false
    fn add_resources(
        &mut self,
        url: &str,
        permission: &str,
        contracts: &str,
        funcs: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), contracts, funcs];
        self.contract_send_tx(url, "addResources", &values, None, blake2b)
    }

    /// Delete the resources of permission
    ///
    /// param permission: The address of permission
    /// param contracts: The contracts of resource
    /// param funcs: The function signature of resource
    /// return true if successed, otherwise false
    fn delete_resources(
        &mut self,
        url: &str,
        permission: &str,
        contracts: &str,
        funcs: &str,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), contracts, funcs];
        self.contract_send_tx(url, "deleteResources", &values, None, blake2b)
    }
}

impl PermissionManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/PermissionManagement.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241b2";
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
        let values = [remove_0x(address)];
        self.contract_send_tx(url, "deleteNode", &values, None, blake2b)
    }

    /// Get node status
    fn node_status(&self, url: &str, address: &str) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_call(url, "getStatus", &values, None)
    }

    /// Get authorities
    fn get_authorities(&self, url: &str) -> Result<Vec<String>, ToolError>;

    /// Applying to promote nodes as consensus nodes
    fn new_consensus_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx(url, "newNode", &values, None, blake2b)
    }

    /// Approve node upgrades to consensus nodes
    fn approve_node(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx(url, "approveNode", &values, None, blake2b)
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
        let values = [remove_0x(address)];
        self.contract_call(url, "getAQL", &values, None)
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
        let values = [quota_limit.as_str()];
        self.contract_send_tx(url, "setBQL", &values, None, blake2b)
    }

    /// Set default account quota limit
    fn set_default_aql(&mut self, url: &str, quota_limit: u64, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let values = [quota_limit.as_str()];
        self.contract_send_tx(url, "setDefaultAQL", &values, None, blake2b)
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
        let values = [remove_0x(address), quota_limit.as_str()];
        self.contract_send_tx(url, "setAQL", &values, None, blake2b)
    }

    /// Check if the account is admin
    fn is_admin(&self, url: &str, address: &str) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_call(url, "isAdmin", &values, None)
    }

    /// Add admin account
    fn add_admin(&mut self, url: &str, address: &str, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx(url, "addAdmin", &values, None, blake2b)
    }
}

impl QuotaManagementExt for ContractClient {
    fn create(client: Option<Client>) -> Self {
        static ABI: &str = include_str!("../../contract_abi/QuotaManager.abi");
        static ADDRESS: &str = "0x00000000000000000000000000000000013241a3";
        Self::new(client, ADDRESS, ABI)
    }
}
