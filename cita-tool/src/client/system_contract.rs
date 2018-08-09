use client::basic::{Client, ClientExt};
use client::{remove_0x, TransactionOptions};

use std::str::{self, FromStr};

use abi::contract_encode_input;
use error::ToolError;
use ethabi::{Address, Contract};
use rpctypes::JsonRpcResponse;

/// Group Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020009")]
#[contract(path = "../../contract_abi/Group.abi")]
#[contract(name = "GroupExt")]
pub struct GroupClient {
    client: Client,
    address: Address,
    contract: Contract,
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
        name: &str,
        values: &[&str],
        quota: Option<u64>,
        to_addr: Option<Address>,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Call a contract method
    fn contract_call(
        &self,
        name: &str,
        values: &[&str],
        to_addr: Option<Address>,
    ) -> Self::RpcResult;

    /// Call a contract method with a to_address
    fn contract_call_to_address(
        &self,
        function_name: &str,
        values: &[&str],
        address: &str,
    ) -> Self::RpcResult {
        let address = Address::from_str(remove_0x(address)).unwrap();
        self.contract_call(function_name, values, Some(address))
    }
}

/// Group System Contract
pub trait GroupExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Query the information of the group
    fn query_info(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryInfo", &[], address)
    }
    /// Query the name of the group
    fn query_name(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryName", &[], address)
    }
    /// Query the accounts of the group
    fn query_accounts(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryAccounts", &[], address)
    }
    /// Alias for query_child
    fn query_children(&self, address: &str) -> Self::RpcResult {
        self.query_child(address)
    }
    /// Query the children of the group
    fn query_child(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryChild", &[], address)
    }
    /// Alias for query_child_length
    fn query_children_length(&self, address: &str) -> Self::RpcResult {
        self.query_child_length(address)
    }
    /// Query the length of children of the group
    fn query_child_length(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryChildLength", &[], address)
    }
    /// Query the parent of the group
    fn query_parent(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryParent", &[], address)
    }
    /// Check the account in the group
    fn in_group(&self, address: &str, account_address: &str) -> Self::RpcResult {
        self.contract_call_to_address("inGroup", &[account_address], address)
    }
}

/// Group manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff02000a")]
#[contract(path = "../../contract_abi/GroupManagement.abi")]
#[contract(name = "GroupManagementExt")]
pub struct GroupManageClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// GroupManagement System Contract
pub trait GroupManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Create a new group
    fn new_group(
        &mut self,
        origin: &str,
        name: &str,
        accounts: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), name, accounts];
        self.contract_send_tx("newGroup", &values, quota, None, blake2b)
    }

    /// Delete the group
    fn delete_group(
        &mut self,
        origin: &str,
        target: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target)];
        self.contract_send_tx("deleteGroup", &values, quota, None, blake2b)
    }

    /// Update the group name
    fn update_group_name(
        &mut self,
        origin: &str,
        target: &str,
        name: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target), name];
        self.contract_send_tx("updateGroupName", &values, quota, None, blake2b)
    }

    /// Add accounts
    fn add_accounts(
        &mut self,
        origin: &str,
        target: &str,
        accounts: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target), accounts];
        self.contract_send_tx("addAccounts", &values, quota, None, blake2b)
    }

    /// Delete accounts
    fn delete_accounts(
        &mut self,
        origin: &str,
        target: &str,
        accounts: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target), accounts];
        self.contract_send_tx("deleteAccounts", &values, quota, None, blake2b)
    }

    /// Check the target group in the scope of the origin group
    ///   Scope: the origin group is the ancestor of the target group
    fn check_scope(&self, origin: &str, target: &str) -> Self::RpcResult {
        let values = [remove_0x(origin), remove_0x(target)];
        self.contract_call("checkScope", &values, None)
    }

    /// Query all groups
    fn query_groups(&self) -> Self::RpcResult {
        self.contract_call("queryGroups", &[], None)
    }
}

/// Role Client
#[derive(ContractExt)]
#[contract(addr = "0x")]
#[contract(path = "../../contract_abi/Role.abi")]
#[contract(name = "RoleExt")]
pub struct RoleClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// Role system contract
pub trait RoleExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Query the information of the role
    ///
    /// return The information of role: name and permissions
    fn query_role(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryRole", &[], address)
    }

    /// Query the name of the role
    ///
    /// return The name of role
    fn query_name(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryName", &[], address)
    }

    /// Query the permissions of the role
    ///
    /// return The permissions of role
    fn query_permissions(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryPermissions", &[], address)
    }

    /// Query the length of the permissions
    ///
    /// return The number of permission
    fn length_of_permissions(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("lengthOfPermissions", &[], address)
    }

    /// Check the duplicate permission
    ///
    /// return true if in permissions, otherwise false
    fn in_permissions(&self, address: &str, permission: &str) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_call_to_address("inPermissions", &values, address)
    }
}

/// Role manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020008")]
#[contract(path = "../../contract_abi/RoleManagement.abi")]
#[contract(name = "RoleManagementExt")]
pub struct RoleManageClient {
    client: Client,
    address: Address,
    contract: Contract,
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
        name: &str,
        permissions: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [name, permissions];
        self.contract_send_tx("newRole", &values, quota, None, blake2b)
    }

    /// Delete the role
    ///
    /// param role: The address of role
    /// return true if successed, otherwise false
    fn delete_role(&mut self, role: &str, quota: Option<u64>, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(role)];
        self.contract_send_tx("deleteRole", &values, quota, None, blake2b)
    }

    /// Update role's name
    ///
    /// param role: The address of role
    /// param name: The new name of role
    /// return true if successed, otherwise false
    fn update_role_name(
        &mut self,
        role: &str,
        name: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), name];
        self.contract_send_tx("updateRoleName", &values, quota, None, blake2b)
    }

    /// Add permissions of role
    ///
    /// param role: The address of role
    /// param permissions: The permissions of role
    /// return true if successed, otherwise false
    fn add_permissions(
        &mut self,
        role: &str,
        permissions: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), permissions];
        self.contract_send_tx("addPermissions", &values, quota, None, blake2b)
    }

    /// Delete permissions of role
    ///
    /// param role: The address of role
    /// param permissions: The permissions of role
    /// return true if successed, otherwise false
    fn delete_permissions(
        &mut self,
        role: &str,
        permissions: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(role), permissions];
        self.contract_send_tx("deletePermissions", &values, quota, None, blake2b)
    }

    /// Set the role to the account
    ///
    /// param account: The account to be setted
    /// param role: The role to be setted
    /// return true if successed, otherwise false
    fn set_role(
        &mut self,
        account: &str,
        role: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(role)];
        self.contract_send_tx("setRole", &values, quota, None, blake2b)
    }

    /// Cancel the account's role
    ///
    /// param account: The account to be canceled
    /// param role: The role to be canceled
    /// return true if successed, otherwise false
    fn cancel_role(
        &mut self,
        account: &str,
        role: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(role)];
        self.contract_send_tx("cancelRole", &values, quota, None, blake2b)
    }

    /// Clear the account's role
    ///
    /// param account: The account to be cleared
    /// return true if successed, otherwise false
    fn clear_role(&mut self, account: &str, quota: Option<u64>, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_send_tx("clearRole", &values, quota, None, blake2b)
    }

    /// Query the roles of the account
    ///
    /// param account: The account to be queried
    /// return The roles of the account
    fn query_roles(&self, account: &str) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_call("queryRoles", &values, None)
    }

    /// Query the accounts that have the role
    ///
    /// param role: The role to be queried
    /// return The accounts that have the role
    fn query_accounts(&self, role: &str) -> Self::RpcResult {
        let values = [remove_0x(role)];
        self.contract_call("queryAccounts", &values, None)
    }
}

/// Role manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020006")]
#[contract(path = "../../contract_abi/Authorization.abi")]
#[contract(name = "AuthorizationExt")]
pub struct AuthorizationClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// Authorization system contract
pub trait AuthorizationExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Query the account's permissions
    ///
    /// param account: The account to be queried
    /// return The permissions of account
    fn query_permissions(&self, account: &str) -> Self::RpcResult {
        let values = [remove_0x(account)];
        self.contract_call("queryPermissions", &values, None)
    }

    /// Query the permission's accounts
    ///
    /// param permission: The permission to be queried
    /// return The accounts of permission
    fn query_accounts(&self, permission: &str) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_call("queryAccounts", &values, None)
    }

    /// Query all accounts
    ///
    /// return All the accounts
    fn query_all_accounts(&self) -> Self::RpcResult {
        self.contract_call("queryAllAccounts", &[], None)
    }

    /// Check Resource
    ///
    /// param account: The account to be checked
    /// param contract: The contract of resource
    /// param func: The function signature of resource
    /// return true if passed, otherwise false
    fn check_resource(&self, account: &str, contract: &str, func: &str) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(contract), remove_0x(func)];
        self.contract_call("checkResource", &values, None)
    }

    /// Check account has a permission
    ///
    /// param _account The account to be checked
    /// param _permission The address of permission
    /// return true if passed, otherwise false
    fn check_permission(&self, account: &str, permission: &str) -> Self::RpcResult {
        let values = [remove_0x(account), remove_0x(permission)];
        self.contract_call("checkPermission", &values, None)
    }
}

/// Permission Client
#[derive(ContractExt)]
#[contract(addr = "0x")]
#[contract(path = "../../contract_abi/Permission.abi")]
#[contract(name = "PermissionExt")]
pub struct PermissionClient {
    client: Client,
    address: Address,
    contract: Contract,
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
    fn in_permission(&self, address: &str, contract: &str, func: &str) -> Self::RpcResult {
        let values = [remove_0x(contract), remove_0x(func)];
        self.contract_call_to_address("inPermission", &values, address)
    }

    /// Query the information of the permission
    ///
    /// return The information of permission: name and resources
    fn query_info(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryInfo", &[], address)
    }

    /// Query the name of the permission
    ///
    /// return The name of permission
    fn query_name(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryName", &[], address)
    }

    /// Query the resource of the permission
    ///
    /// return The resources of permission
    fn query_resource(&self, address: &str) -> Self::RpcResult {
        self.contract_call_to_address("queryResource", &[], address)
    }
}

/// Permission manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020004")]
#[contract(path = "../../contract_abi/PermissionManagement.abi")]
#[contract(name = "PermissionManagementExt")]
pub struct PermissionManageClient {
    client: Client,
    address: Address,
    contract: Contract,
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
        name: &str,
        contracts: &str,
        funcs: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [name, contracts, funcs];
        self.contract_send_tx("newPermission", &values, quota, None, blake2b)
    }

    /// Delete the permission
    ///
    /// param permission: The address of permission
    /// return true if successed, otherwise false
    fn delete_permission(
        &mut self,
        permission: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission)];
        self.contract_send_tx("deletePermission", &values, quota, None, blake2b)
    }

    /// Update the permission name
    ///
    /// param permission: The address of permission
    /// param name: The new name
    /// return true if successed, otherwise false
    fn update_permission_name(
        &mut self,
        permission: &str,
        name: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), name];
        self.contract_send_tx("updatePermissionName", &values, quota, None, blake2b)
    }

    /// Add the resources of permission
    ///
    /// param permission: The address of permission
    /// param contracts: The contracts of resource
    /// param funcs: The function signature of resource
    /// return true if successed, otherwise false
    fn add_resources(
        &mut self,
        permission: &str,
        contracts: &str,
        funcs: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), contracts, funcs];
        self.contract_send_tx("addResources", &values, quota, None, blake2b)
    }

    /// Delete the resources of permission
    ///
    /// param permission: The address of permission
    /// param contracts: The contracts of resource
    /// param funcs: The function signature of resource
    /// return true if successed, otherwise false
    fn delete_resources(
        &mut self,
        permission: &str,
        contracts: &str,
        funcs: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(permission), contracts, funcs];
        self.contract_send_tx("deleteResources", &values, quota, None, blake2b)
    }

    /// Set permission to the account
    ///
    /// param account: The account to be setted
    /// param permission: The permission to be setted
    /// return true if success, otherwise false
    fn set_authorization(
        &mut self,
        account_address: &str,
        permission: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account_address), remove_0x(permission)];
        self.contract_send_tx("setAuthorization", &values, quota, None, blake2b)
    }

    /// Set multiple permissions to the account
    ///
    /// param account: The account to be setted
    /// param permissions: The multiple permissions to be setted
    /// return true if success, otherwise false
    fn set_authorizations(
        &mut self,
        account_address: &str,
        permissions: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account_address), permissions];
        self.contract_send_tx("setAuthorizations", &values, quota, None, blake2b)
    }

    /// Cancel the account's permission
    ///
    /// param account: The account to be canceled
    /// param permissions: The permission to be canceled
    /// return true if success, otherwise false
    fn cancel_authorization(
        &mut self,
        account_address: &str,
        permission: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account_address), remove_0x(permission)];
        self.contract_send_tx("cancelAuthorization", &values, quota, None, blake2b)
    }

    /// Cancel the account's multiple permission
    ///
    /// param account: The account to be canceled
    /// param permissions: The multiple permissions to be canceled
    /// return true if success, otherwise false
    fn cancel_authorizations(
        &mut self,
        account_address: &str,
        permissions: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account_address), permissions];
        self.contract_send_tx("cancelAuthorizations", &values, quota, None, blake2b)
    }

    /// Clear the account's permissions
    ///
    /// param account: The account to be cleared
    /// return true if success, otherwise false
    fn clear_authorization(
        &mut self,
        account_address: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(account_address)];
        self.contract_send_tx("clearAuthorization", &values, quota, None, blake2b)
    }
}

/// Node manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020001")]
#[contract(path = "../../contract_abi/NodeManager.abi")]
#[contract(name = "NodeManagementExt")]
pub struct NodeManageClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// NodeManager system contract
pub trait NodeManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Downgrade consensus node to ordinary node
    fn downgrade_consensus_node(
        &mut self,
        address: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx("deleteNode", &values, quota, None, blake2b)
    }

    /// Get node status
    fn node_status(&self, address: &str) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_call("getStatus", &values, None)
    }

    /// Get authorities
    fn get_authorities(&self) -> Self::RpcResult {
        self.contract_call("listNode", &[], None)
    }

    /// Approve node upgrades to consensus nodes
    fn approve_node(
        &mut self,
        address: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx("approveNode", &values, quota, None, blake2b)
    }

    /// Node stake list
    fn list_stake(&self) -> Self::RpcResult {
        self.contract_call("listStake", &[], None)
    }

    /// Set node stake
    fn set_stake(
        &mut self,
        address: &str,
        stake: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let values = [remove_0x(address), stake];
        self.contract_send_tx("setStake", &values, quota, None, blake2b)
    }

    /// Stake permillage
    fn stake_permillage(&self, address: &str) -> Self::RpcResult {
        self.contract_call("stakePermillage", &[remove_0x(address)], None)
    }
}

/// Node manage Client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff020003")]
#[contract(path = "../../contract_abi/QuotaManager.abi")]
#[contract(name = "QuotaManagementExt")]
pub struct QuotaManageClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// QuotaManager system contract
pub trait QuotaManagementExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Get block quota upper limit
    fn get_bql(&self) -> Self::RpcResult {
        self.contract_call("getBQL", &[], None)
    }

    /// Get account quota upper limit of the specific account
    fn get_aql(&self, address: &str) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_call("getAQL", &values, None)
    }

    /// Get default account quota limit
    fn get_default_aql(&self) -> Self::RpcResult {
        self.contract_call("getDefaultAQL", &[], None)
    }

    /// Get accounts
    fn get_accounts(&self) -> Self::RpcResult {
        self.contract_call("getAccounts", &[], None)
    }

    /// Get quotas
    fn get_quotas(&self) -> Self::RpcResult {
        self.contract_call("getQuotas", &[], None)
    }

    /// Set block quota limit
    fn set_bql(&mut self, quota_limit: u64, quota: Option<u64>, blake2b: bool) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let values = [quota_limit.as_str()];
        self.contract_send_tx("setBQL", &values, quota, None, blake2b)
    }

    /// Set default account quota limit
    fn set_default_aql(
        &mut self,
        quota_limit: u64,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let values = [quota_limit.as_str()];
        self.contract_send_tx("setDefaultAQL", &values, quota, None, blake2b)
    }

    /// Set account quota upper limit of the specific account
    fn set_aql(
        &mut self,
        address: &str,
        quota_limit: u64,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let quota_limit = format!("{}", quota_limit);
        let values = [remove_0x(address), quota_limit.as_str()];
        self.contract_send_tx("setAQL", &values, quota, None, blake2b)
    }
}

/// Admin manage client
#[derive(ContractExt)]
#[contract(addr = "0xffffffffffffffffffffffffffffffffff02000c")]
#[contract(path = "../../contract_abi/Admin.abi")]
#[contract(name = "AdminExt")]
pub struct AdminClient {
    client: Client,
    address: Address,
    contract: Contract,
}

/// Admin system contract
pub trait AdminExt: ContractCall {
    /// Create a ContractClient
    fn create(client: Option<Client>) -> Self;

    /// Get admin address
    fn admin(&self) -> Self::RpcResult {
        self.contract_call("admin", &[], None)
    }

    /// Check if the account is admin
    fn is_admin(&self, address: &str) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_call("isAdmin", &values, None)
    }

    /// Update admin account
    fn add_admin(&mut self, address: &str, quota: Option<u64>, blake2b: bool) -> Self::RpcResult {
        let values = [remove_0x(address)];
        self.contract_send_tx("update", &values, quota, None, blake2b)
    }
}
