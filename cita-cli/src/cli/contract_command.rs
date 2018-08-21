use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::client::basic::Client;
use cita_tool::client::system_contract::{
    AdminClient, AdminExt, AuthorizationClient, BatchTxClient, GroupClient, GroupManageClient,
    NodeManageClient, PermissionClient, PermissionManageClient, QuotaManageClient, RoleClient,
    RoleManageClient,
};
use cita_tool::client::system_contract::{
    AuthorizationExt, BatchTxExt, GroupExt, GroupManagementExt, NodeManagementExt, PermissionExt,
    PermissionManagementExt, QuotaManagementExt, RoleExt, RoleManagementExt,
};

use cli::{blake2b, get_url, is_hex, parse_privkey, parse_u64};
use interactive::GlobalConfig;
use printer::Printer;

/// System contract
pub fn contract_command() -> App<'static, 'static> {
    let address_arg = Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()));
    let name_arg = Arg::with_name("name")
        .long("name")
        .takes_value(true)
        .required(true);
    let quota_arg = Arg::with_name("quota")
        .long("quota")
        .takes_value(true)
        .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
        .help("Transaction quota costs");

    let group_address_arg = address_arg.clone().help("Group address");
    let group_name_arg = name_arg.clone().help("Group name");
    let group_origin_arg = Arg::with_name("origin")
        .long("origin")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Group origin address");
    let group_target_arg = Arg::with_name("target")
        .long("target")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Group target address");
    let group_accounts_arg = Arg::with_name("accounts")
        .long("accounts")
        .takes_value(true)
        .required(true)
        .help("Group account address list");

    let account_address_arg = Arg::with_name("account")
        .long("account")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Account address");
    let contract_address_arg = Arg::with_name("contract")
        .long("contract")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("The contract address");
    let function_hash_arg = Arg::with_name("function-hash")
        .long("function-hash")
        .takes_value(true)
        .required(true)
        .validator(|hash| is_hex(hash.as_ref()))
        .help("The function hash");
    let contracts_address_arg = Arg::with_name("contracts")
        .long("contracts")
        .takes_value(true)
        .required(true)
        .help("Contract address list");
    let function_hashes_arg = Arg::with_name("function-hashes")
        .long("function-hashes")
        .takes_value(true)
        .required(true)
        .help("Function hash list");
    let private_key = Arg::with_name("private-key")
        .long("private-key")
        .takes_value(true)
        .required(true)
        .validator(|private_key| parse_privkey(private_key.as_ref()).map(|_| ()))
        .help("Private key");

    let role_address_arg = address_arg.clone().help("Role address");
    let role_name_arg = name_arg.clone().help("Role name");

    let permission_address_arg = Arg::with_name("permission")
        .long("permission")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Permission address");
    let permission_name_arg = name_arg.clone().help("Permission name");
    // TODO: how to deal with complex ethabi value like an array
    let permissions_address_arg = Arg::with_name("permissions")
        .long("permissions")
        .takes_value(true)
        .required(true)
        .help("Permission address list");

    App::new("scm")
        .about("System contract manager")
        .subcommand(
            SubCommand::with_name("NodeManager")
                .subcommand(SubCommand::with_name("listNode"))
                .subcommand(SubCommand::with_name("listStake"))
                .subcommand(
                    SubCommand::with_name("getStatus").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Node address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("deleteNode")
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Degraded node address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("approveNode")
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Approve node address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setStake")
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("stake")
                                .long("stake")
                                .takes_value(true)
                                .required(true)
                                .validator(|stake| parse_u64(stake.as_ref()).map(|_| ()))
                                .help("The stake you want to set"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Set address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("stakePermillage").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Query address"),
                    ),
                ),
        )
        .subcommand(
            SubCommand::with_name("QuotaManager")
                .subcommand(SubCommand::with_name("getBQL"))
                .subcommand(SubCommand::with_name("getDefaultAQL"))
                .subcommand(SubCommand::with_name("getAccounts"))
                .subcommand(SubCommand::with_name("getQuotas"))
                .subcommand(
                    SubCommand::with_name("getAQL").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Account address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("setBQL")
                        .arg(
                            Arg::with_name("quota-limit")
                                .long("quota-limit")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 28 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setDefaultAQL")
                        .arg(
                            Arg::with_name("quota-limit")
                                .long("quota-limit")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 22 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setAQL")
                        .arg(
                            Arg::with_name("quota-limit")
                                .long("quota-limit")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 22 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Account address"),
                        )
                        .arg(quota_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("GroupManagement")
                .about("User management using group struct (group_management.sol)")
                .subcommand(
                    SubCommand::with_name("newGroup")
                        .arg(group_origin_arg.clone())
                        .arg(group_name_arg.clone())
                        .arg(group_accounts_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteGroup")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("updateGroupName")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_name_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("addAccounts")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_accounts_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteAccounts")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_accounts_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("checkScope")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone()),
                )
                .subcommand(SubCommand::with_name("queryGroups")),
        )
        .subcommand(
            SubCommand::with_name("Group")
                .about("Group contract (group.sol)")
                .subcommand(
                    SubCommand::with_name("queryInfo")
                        .about("Query the information of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the accounts of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChild")
                        .about("Query the child of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChildLength")
                        .about("Query the length of children of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryParent")
                        .about("Query the parent of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("inGroup")
                        .about("Check the account in the group")
                        .arg(group_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("Role")
                .about("Role.sol")
                .subcommand(
                    SubCommand::with_name("queryRole")
                        .about("Query the information of the role")
                        .arg(role_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the role")
                        .arg(role_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryPermissions")
                        .about("Query the permissions of the role")
                        .arg(role_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("lengthOfPermissions")
                        .about("Query the length of the permissions")
                        .arg(role_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("inPermissions")
                        .about("Check the duplicate permission")
                        .arg(role_address_arg.clone())
                        .arg(permission_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("RoleManagement")
                .about("RoleManagement.sol")
                .subcommand(
                    SubCommand::with_name("newRole")
                        .about("Create a new role")
                        .arg(role_name_arg.clone())
                        .arg(permissions_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteRole")
                        .about("Delete the role")
                        .arg(role_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("updateRoleName")
                        .about("Update role's name")
                        .arg(role_address_arg.clone())
                        .arg(role_name_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("addPermissions")
                        .about("Add permissions of role")
                        .arg(role_address_arg.clone())
                        .arg(permissions_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deletePermissions")
                        .about("Delete permissions of role")
                        .arg(role_address_arg.clone())
                        .arg(permissions_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setRole")
                        .about("Set the role to the account")
                        .arg(account_address_arg.clone())
                        .arg(role_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("cancelRole")
                        .about("Cancel the account's role")
                        .arg(account_address_arg.clone())
                        .arg(role_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("clearRole")
                        .about("Clear the account's role")
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryRoles")
                        .about("Query the roles of the account")
                        .arg(account_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the accounts that have the role")
                        .arg(role_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("Authorization")
                .about("Authorization.sol")
                .subcommand(
                    SubCommand::with_name("queryPermissions")
                        .about("Query the account's permissions")
                        .arg(account_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the permission's accounts")
                        .arg(permission_address_arg.clone()),
                )
                .subcommand(SubCommand::with_name("queryAllAccounts").about("Query all accounts"))
                .subcommand(
                    SubCommand::with_name("checkResource")
                        .about("Check Resource")
                        .arg(account_address_arg.clone())
                        .arg(contract_address_arg.clone())
                        .arg(function_hash_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("checkPermission")
                        .about("Check Permission")
                        .arg(account_address_arg.clone())
                        .arg(permission_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("Permission")
                .about("Permission.sol")
                .subcommand(
                    SubCommand::with_name("inPermission")
                        .about("Check resource in the permission")
                        .arg(permission_address_arg.clone())
                        .arg(contract_address_arg.clone())
                        .arg(function_hash_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryInfo")
                        .about("Query the information of the permission")
                        .arg(permission_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the permission")
                        .arg(permission_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryResource")
                        .about("Query the resource of the permission")
                        .arg(permission_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("PermissionManagement")
                .about("PermissionManagement.sol")
                .subcommand(
                    SubCommand::with_name("newPermission")
                        .about("Create a new permission")
                        .arg(permission_name_arg.clone())
                        .arg(contracts_address_arg.clone())
                        .arg(function_hashes_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deletePermission")
                        .about("Delete the permission")
                        .arg(permission_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("updatePermissionName")
                        .about("Update the permission name")
                        .arg(permission_address_arg.clone())
                        .arg(permission_name_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("addResources")
                        .about("Add the resources of permission")
                        .arg(permission_address_arg.clone())
                        .arg(contracts_address_arg.clone())
                        .arg(function_hashes_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteResources")
                        .about("Delete the resources of permission")
                        .arg(permission_address_arg.clone())
                        .arg(contracts_address_arg.clone())
                        .arg(function_hashes_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setAuthorization")
                        .about("Set permission to the account")
                        .arg(permission_address_arg.clone())
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setAuthorizations")
                        .about("Set multiple permissions to the account")
                        .arg(permissions_address_arg.clone())
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("cancelAuthorization")
                        .about("Cancel the account's permission")
                        .arg(permission_address_arg.clone())
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("cancelAuthorizations")
                        .about("Cancel the account's multiple permission")
                        .arg(permissions_address_arg.clone())
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                )
                .subcommand(
                    SubCommand::with_name("clearAuthorization")
                        .about("Clear the account's permissions")
                        .arg(account_address_arg.clone())
                        .arg(quota_arg.clone())
                        .arg(private_key.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("AdminManagement")
                .subcommand(SubCommand::with_name("admin"))
                .subcommand(
                    SubCommand::with_name("isAdmin").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Account address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Account address"),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(quota_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("BatchTx").subcommand(
                SubCommand::with_name("multiTxs")
                    .arg(
                        Arg::with_name("tx-code")
                            .long("tx-code")
                            .takes_value(true)
                            .required(true)
                            .multiple(true)
                            .validator(|code| is_hex(code.as_str()))
                            .help("Binary content of one transaction[address + encode(function + params)]"),
                    )
                    .arg(quota_arg.clone())
                    .arg(private_key.clone()),
            ),
        )
}

/// System contract processor
pub fn contract_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug)
        .set_uri(url.unwrap_or_else(|| match sub_matches.subcommand() {
            (_, Some(m)) => get_url(m),
            _ => "http://127.0.0.1:1337",
        }));

    let result = match sub_matches.subcommand() {
        ("NodeManager", Some(m)) => match m.subcommand() {
            ("listNode", _) => {
                let client = NodeManageClient::create(Some(client));
                client.get_authorities()
            }
            ("listStake", _) => {
                let client = NodeManageClient::create(Some(client));
                client.list_stake()
            }
            ("getStatus", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = NodeManageClient::create(Some(client));
                client.node_status(address)
            }
            ("deleteNode", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let mut client = NodeManageClient::create(Some(client));
                client.downgrade_consensus_node(address, quota, blake2b)
            }
            ("approveNode", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let mut client = NodeManageClient::create(Some(client));
                client.approve_node(address, quota, blake2b)
            }
            ("setStake", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let stake = m
                    .value_of("stake")
                    .map(|stake| parse_u64(stake).unwrap().to_string())
                    .unwrap();
                let mut client = NodeManageClient::create(Some(client));
                client.set_stake(address, &stake, quota, blake2b)
            }
            ("stakePermillage", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = NodeManageClient::create(Some(client));
                client.stake_permillage(address)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("QuotaManager", Some(m)) => match m.subcommand() {
            ("getBQL", _) => QuotaManageClient::create(Some(client)).get_bql(),
            ("getDefaultAQL", _) => QuotaManageClient::create(Some(client)).get_default_aql(),
            ("getAccounts", _) => QuotaManageClient::create(Some(client)).get_accounts(),
            ("getQuotas", _) => QuotaManageClient::create(Some(client)).get_quotas(),
            ("getAQL", Some(m)) => {
                let address = m.value_of("address").unwrap();
                QuotaManageClient::create(Some(client)).get_aql(address)
            }
            ("setBQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota_limit = parse_u64(m.value_of("quota-limit").unwrap())?;
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(Some(client)).set_bql(quota_limit, quota, blake2b)
            }
            ("setDefaultAQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota_limit = parse_u64(m.value_of("quota-limit").unwrap())?;
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(Some(client)).set_default_aql(quota_limit, quota, blake2b)
            }
            ("setAQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota_limit = parse_u64(m.value_of("quota-limit").unwrap())?;
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(Some(client)).set_aql(
                    address,
                    quota_limit,
                    quota,
                    blake2b,
                )
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Group", Some(m)) => match m.subcommand() {
            ("queryInfo", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(Some(client));
                GroupExt::query_info(&client, address)
            }
            ("queryName", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(Some(client));
                GroupExt::query_name(&client, address)
            }
            ("queryAccounts", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(Some(client));
                GroupExt::query_accounts(&client, address)
            }
            ("queryChild", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(Some(client)).query_child(address)
            }
            ("queryChildLength", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(Some(client)).query_child_length(address)
            }
            ("queryParent", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(Some(client)).query_parent(address)
            }
            ("inGroup", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let account_address = m.value_of("account").unwrap();
                GroupClient::create(Some(client)).in_group(address, account_address)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("GroupManagement", Some(m)) => match m.subcommand() {
            ("newGroup", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let origin = m.value_of("origin").unwrap();
                let name = m.value_of("name").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = GroupManageClient::create(Some(client));
                client.new_group(origin, name, accounts, quota, blake2b)
            }
            ("deleteGroup", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = GroupManageClient::create(Some(client));
                client.delete_group(origin, target, quota, blake2b)
            }
            ("updateGroupName", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let name = m.value_of("name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = GroupManageClient::create(Some(client));
                client.update_group_name(origin, target, name, quota, blake2b)
            }
            ("addAccounts", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = GroupManageClient::create(Some(client));
                client.add_accounts(origin, target, accounts, quota, blake2b)
            }
            ("deleteAccounts", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = GroupManageClient::create(Some(client));
                client.delete_accounts(origin, target, accounts, quota, blake2b)
            }
            ("checkScope", Some(m)) => {
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let mut client = GroupManageClient::create(Some(client));
                client.check_scope(origin, target)
            }
            ("queryGroups", _) => {
                let mut client = GroupManageClient::create(Some(client));
                client.query_groups()
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Role", Some(m)) => match m.subcommand() {
            ("queryRole", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(Some(client));
                client.query_role(address)
            }
            ("queryName", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(Some(client));
                client.query_name(address)
            }
            ("queryPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(Some(client));
                client.query_permissions(address)
            }
            ("lengthOfPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(Some(client));
                client.length_of_permissions(address)
            }
            ("inPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let permission = m.value_of("permission").unwrap();
                let client = RoleClient::create(Some(client));
                client.in_permissions(address, permission)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("RoleManagement", Some(m)) => match m.subcommand() {
            ("newRole", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let name = m.value_of("name").unwrap();
                let permissions = m.value_of("permissions").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = RoleManageClient::create(Some(client));
                RoleManagementExt::new_role(&mut client, name, permissions, quota, blake2b)
            }
            ("deleteRole", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let account = m.value_of("account").unwrap();
                let role = m.value_of("role").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = RoleManageClient::create(Some(client));
                RoleManagementExt::set_role(&mut client, account, role, quota, blake2b)
            }
            ("cancelRole", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let account = m.value_of("account").unwrap();
                let role = m.value_of("role").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = RoleManageClient::create(Some(client));
                RoleManagementExt::cancel_role(&mut client, account, role, quota, blake2b)
            }
            ("clearRole", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = RoleManageClient::create(Some(client));
                RoleManagementExt::clear_role(&mut client, account, quota, blake2b)
            }
            ("queryRoles", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let client = RoleManageClient::create(Some(client));
                RoleManagementExt::query_roles(&client, account)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Authorization", Some(m)) => match m.subcommand() {
            ("queryPermissions", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let client = AuthorizationClient::create(Some(client));
                AuthorizationExt::query_permissions(&client, account)
            }
            ("queryAccounts", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = AuthorizationClient::create(Some(client));
                AuthorizationExt::query_accounts(&client, permission)
            }
            ("queryAllAccounts", _) => {
                let client = AuthorizationClient::create(Some(client));
                AuthorizationExt::query_all_accounts(&client)
            }
            ("checkResource", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let contract = m.value_of("contract").unwrap();
                let function_hash = m.value_of("function-hash").unwrap();
                let client = AuthorizationClient::create(Some(client));
                AuthorizationExt::check_resource(&client, account, contract, function_hash)
            }
            ("checkPermission", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let permission = m.value_of("permission").unwrap();
                let client = AuthorizationClient::create(Some(client));
                AuthorizationExt::check_permission(&client, account, permission)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Permission", Some(m)) => match m.subcommand() {
            ("inPermission", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let contract = m.value_of("contract").unwrap();
                let function_hash = m.value_of("function-hash").unwrap();
                let client = PermissionClient::create(Some(client));
                PermissionExt::in_permission(&client, permission, contract, function_hash)
            }
            ("queryInfo", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(Some(client));
                PermissionExt::query_info(&client, permission)
            }
            ("queryName", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(Some(client));
                PermissionExt::query_name(&client, permission)
            }
            ("queryResource", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(Some(client));
                PermissionExt::query_resource(&client, permission)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("PermissionManagement", Some(m)) => match m.subcommand() {
            ("newPermission", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let name = m.value_of("name").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::new_permission(
                    &mut client,
                    name,
                    contracts,
                    function_hashes,
                    quota,
                    blake2b,
                )
            }
            ("deletePermission", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::delete_permission(&mut client, permission, quota, blake2b)
            }
            ("updatePermissionName", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let name = m.value_of("name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::update_permission_name(
                    &mut client,
                    permission,
                    name,
                    quota,
                    blake2b,
                )
            }
            ("addResources", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::add_resources(
                    &mut client,
                    permission,
                    contracts,
                    function_hashes,
                    quota,
                    blake2b,
                )
            }
            ("deleteResources", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::delete_resources(
                    &mut client,
                    permission,
                    contracts,
                    function_hashes,
                    quota,
                    blake2b,
                )
            }
            ("setAuthorization", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::set_authorization(
                    &mut client,
                    account,
                    permission,
                    quota,
                    blake2b,
                )
            }
            ("setAuthorizations", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permissions = m.value_of("permissions").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::set_authorizations(
                    &mut client,
                    account,
                    permissions,
                    quota,
                    blake2b,
                )
            }
            ("cancelAuthorization", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permission = m.value_of("permission").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::cancel_authorization(
                    &mut client,
                    account,
                    permission,
                    quota,
                    blake2b,
                )
            }
            ("cancelAuthorizations", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let permissions = m.value_of("permissions").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::cancel_authorizations(
                    &mut client,
                    account,
                    permissions,
                    quota,
                    blake2b,
                )
            }
            ("clearAuthorization", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let mut client = PermissionManageClient::create(Some(client));
                PermissionManagementExt::clear_authorization(&mut client, account, quota, blake2b)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("AdminManagement", Some(m)) => match m.subcommand() {
            ("admin", _) => AdminClient::create(Some(client)).admin(),
            ("isAdmin", Some(m)) => {
                let address = m.value_of("address").unwrap();
                AdminClient::create(Some(client)).is_admin(address)
            }
            ("update", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let address = m.value_of("address").unwrap();
                AdminClient::create(Some(client)).add_admin(address, quota, blake2b)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("BatchTx", Some(m)) => match m.subcommand() {
            ("multiTxs", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(&parse_privkey(m.value_of("private-key").unwrap())?);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let txs = m.values_of("tx-code").map(|value| value.collect()).unwrap();
                BatchTxClient::create(Some(client)).multi_transactions(txs, quota, blake2b)
            }
            _ => return Err(m.usage().to_owned()),
        },
        _ => return Err(sub_matches.usage().to_owned()),
    };
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    let response = result.map_err(|err| format!("{}", err))?;
    printer.println(&response, is_color);
    Ok(())
}
