use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::client::basic::Client;
use cita_tool::client::system_contract::{
    AdminClient, AdminExt, AuthorizationClient, BatchTxClient, EmergencyBrakeClient, GroupClient,
    GroupManageClient, NodeManageClient, PermissionClient, PermissionManageClient,
    PriceManagerClient, QuotaManageClient, RoleClient, RoleManageClient, SysConfigClient,
    VersionManagerClient,
};
use cita_tool::client::system_contract::{
    AuthorizationExt, BatchTxExt, EmergencyBrakeExt, GroupExt, GroupManagementExt,
    NodeManagementExt, PermissionExt, PermissionManagementExt, PriceManagerExt, QuotaManagementExt,
    RoleExt, RoleManagementExt, SysConfigExt, VersionManagerExt,
};

use crate::cli::{
    encryption, get_url, is_hex, key_validator, parse_address, parse_height, parse_privkey,
    parse_u256, parse_u64,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;

/// System contract
pub fn contract_command() -> App<'static, 'static> {
    let address_arg = Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .required(true)
        .validator(|address| parse_address(address.as_str()));
    let name_arg = Arg::with_name("name")
        .long("name")
        .takes_value(true)
        .required(true);
    let quota_arg = Arg::with_name("quota")
        .long("quota")
        .takes_value(true)
        .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
        .help("Transaction quota costs, default 10_000_000");
    let height_arg = Arg::with_name("height")
        .long("height")
        .default_value("latest")
        .validator(|s| parse_height(s.as_str()))
        .takes_value(true)
        .help("The number of the block");

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
        .validator(|address| parse_address(address.as_str()))
        .help("Account address");
    let contract_address_arg = Arg::with_name("contract")
        .long("contract")
        .takes_value(true)
        .required(true)
        .validator(|address| parse_address(address.as_str()))
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
        .validator(|private_key| key_validator(private_key.as_ref()).map(|_| ()))
        .help("Private key");
    let admin_private = Arg::with_name("admin-private")
        .long("admin-private")
        .takes_value(true)
        .required(true)
        .validator(|private_key| key_validator(private_key.as_ref()).map(|_| ()))
        .help("Private key must be admin");

    let role_address_arg = address_arg.clone().help("Role address");
    let role_name_arg = name_arg.clone().help("Role name");

    let permission_address_arg = Arg::with_name("permission")
        .long("permission")
        .takes_value(true)
        .required(true)
        .validator(|address| parse_address(address.as_str()))
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
                .subcommand(SubCommand::with_name("listNode").arg(height_arg.clone()))
                .subcommand(SubCommand::with_name("listStake").arg(height_arg.clone()))
                .subcommand(
                    SubCommand::with_name("getStatus").arg(
                        address_arg.clone().help("Node address"),
                    ).arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteNode")
                        .arg(admin_private.clone())
                        .arg(
                            address_arg.clone().help("Degraded node address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("approveNode")
                        .arg(admin_private.clone())
                        .arg(
                            address_arg.clone().help("Approve node address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("setStake")
                        .arg(admin_private.clone())
                        .arg(
                            Arg::with_name("stake")
                                .long("stake")
                                .takes_value(true)
                                .required(true)
                                .validator(|stake| parse_u64(stake.as_ref()).map(|_| ()))
                                .help("The stake you want to set"),
                        )
                        .arg(
                            address_arg.clone().help("Set address"),
                        )
                        .arg(quota_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("stakePermillage").arg(
                        address_arg.clone().help("Query address"),
                    ).arg(height_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("QuotaManager")
                .subcommand(SubCommand::with_name("getBQL").arg(height_arg.clone()))
                .subcommand(SubCommand::with_name("getDefaultAQL").arg(height_arg.clone()))
                .subcommand(SubCommand::with_name("getAccounts").arg(height_arg.clone()))
                .subcommand(SubCommand::with_name("getQuotas").arg(height_arg.clone()))
                .subcommand(
                    SubCommand::with_name("getAQL").arg(
                        address_arg.clone().help("Account address"),
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
                        .arg(admin_private.clone())
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
                        .arg(admin_private.clone())
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
                        .arg(admin_private.clone())
                        .arg(
                            address_arg.clone().help("Account address"),
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
                        .arg(group_target_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(SubCommand::with_name("queryGroups").arg(height_arg.clone())),
        )
        .subcommand(
            SubCommand::with_name("Group")
                .about("Group contract (group.sol)")
                .subcommand(
                    SubCommand::with_name("queryInfo")
                        .about("Query the information of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the accounts of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChild")
                        .about("Query the child of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChildLength")
                        .about("Query the length of children of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryParent")
                        .about("Query the parent of the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("inGroup")
                        .about("Check the account in the group")
                        .arg(group_address_arg.clone())
                        .arg(height_arg.clone())
                        .arg(account_address_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("Role")
                .about("Role.sol")
                .subcommand(
                    SubCommand::with_name("queryRole")
                        .about("Query the information of the role")
                        .arg(role_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the role")
                        .arg(role_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryPermissions")
                        .about("Query the permissions of the role")
                        .arg(role_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("lengthOfPermissions")
                        .about("Query the length of the permissions")
                        .arg(role_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("inPermissions")
                        .about("Check the duplicate permission")
                        .arg(role_address_arg.clone())
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
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
                        .arg(account_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the accounts that have the role")
                        .arg(role_address_arg.clone())
                        .arg(height_arg.clone()),
                ),
        )
        .subcommand(
            SubCommand::with_name("Authorization")
                .about("Authorization.sol")
                .subcommand(
                    SubCommand::with_name("queryPermissions")
                        .about("Query the account's permissions")
                        .arg(account_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the permission's accounts")
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(SubCommand::with_name("queryAllAccounts").arg(height_arg.clone()).about("Query all accounts"))
                .subcommand(
                    SubCommand::with_name("checkResource")
                        .about("Check Resource")
                        .arg(account_address_arg.clone())
                        .arg(contract_address_arg.clone())
                        .arg(function_hash_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("checkPermission")
                        .about("Check Permission")
                        .arg(account_address_arg.clone())
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
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
                        .arg(function_hash_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryInfo")
                        .about("Query the information of the permission")
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the permission")
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryResource")
                        .about("Query the resource of the permission")
                        .arg(permission_address_arg.clone())
                        .arg(height_arg.clone()),
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
                .subcommand(SubCommand::with_name("admin").arg(height_arg.clone()))
                .subcommand(
                    SubCommand::with_name("isAdmin").arg(
                        address_arg.clone().help("Account address"),
                    ).arg(height_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("update")
                        .arg(
                            address_arg.clone().help("Account address"),
                        )
                        .arg(admin_private.clone())
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
        .subcommand(
            SubCommand::with_name("SysConfig").subcommand(
                SubCommand::with_name("getChainOwner")
                    .arg(
                        height_arg.clone()
                    )
            )
                .subcommand(
                    SubCommand::with_name("getChainId")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getChainIdV1")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getDelayBlockNumber")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getFeeBackPlatformCheck")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getEconomicalModel")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getPermissionCheck")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getQuotaCheck")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("setChainName")
                        .arg(
                            Arg::with_name("chain-name")
                                .long("chain-name")
                                .takes_value(true)
                                .required(true)
                                .help("Set chain name")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
                .subcommand(
                    SubCommand::with_name("setOperator")
                        .arg(
                            Arg::with_name("operator")
                                .long("operator")
                                .takes_value(true)
                                .required(true)
                                .help("Set operator")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
                .subcommand(
                    SubCommand::with_name("setWebsite")
                        .arg(
                            Arg::with_name("website")
                                .long("website")
                                .takes_value(true)
                                .required(true)
                                .help("Set website")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
                .subcommand(
                    SubCommand::with_name("setBlockInterval")
                        .arg(
                            Arg::with_name("blockInterval")
                                .long("blockInterval")
                                .takes_value(true)
                                .required(true)
                                .help("Set block interval")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
                .subcommand(
                    SubCommand::with_name("getCreateContractPermissionCheck")
                        .arg(
                            height_arg.clone()
                        )
                )
                .subcommand(
                    SubCommand::with_name("getSendTxPermissionCheck")
                        .arg(
                            height_arg.clone()
                        )
                )
        )
        .subcommand(
            SubCommand::with_name("EmergencyBrake")
                .subcommand(
                    SubCommand::with_name("state").arg(height_arg.clone())
                )
                .subcommand(
                    SubCommand::with_name("setState")
                        .arg(
                            Arg::with_name("state")
                                .long("state")
                                .takes_value(true)
                                .required(true)
                                .validator(|state| state.as_str().parse::<bool>().map(|_| ()).map_err(|err| err.to_string()))
                                .help("State value")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
        )
        .subcommand(
            SubCommand::with_name("PriceManager")
                .subcommand(
                    SubCommand::with_name("getQuotaPrice").arg(height_arg.clone())
                )
                .subcommand(
                    SubCommand::with_name("setQuotaPrice")
                        .arg(
                            Arg::with_name("price")
                                .long("price")
                                .takes_value(true)
                                .required(true)
                                .validator(|price| parse_u256(price.as_ref()).map(|_| ()))
                                .help("Price value")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
        )
        .subcommand(
            SubCommand::with_name("VersionManager")
                .subcommand(
                    SubCommand::with_name("getVersion").arg(height_arg.clone())
                )
                .subcommand(
                    SubCommand::with_name("setVersion")
                        .arg(
                            Arg::with_name("version")
                                .long("version")
                                .takes_value(true)
                                .required(true)
                                .validator(|version| version.as_str().parse::<u32>()
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                                )
                                .help("Version value")
                        )
                        .arg(quota_arg.clone())
                        .arg(admin_private.clone())
                )
        )
}

/// System contract processor
pub fn contract_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let result = match sub_matches.subcommand() {
        ("NodeManager", Some(m)) => match m.subcommand() {
            ("listNode", Some(m)) => {
                let client = NodeManageClient::create(client);
                client.get_authorities(m.value_of("height"))
            }
            ("listStake", Some(m)) => {
                let client = NodeManageClient::create(client);
                client.list_stake(m.value_of("height"))
            }
            ("getStatus", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = NodeManageClient::create(client);
                client.node_status(address, m.value_of("height"))
            }
            ("deleteNode", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let mut client = NodeManageClient::create(client);
                client.downgrade_consensus_node(address, quota)
            }
            ("approveNode", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let mut client = NodeManageClient::create(client);
                client.approve_node(address, quota)
            }
            ("setStake", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let stake = m
                    .value_of("stake")
                    .map(|stake| parse_u256(stake).unwrap())
                    .unwrap();
                let mut client = NodeManageClient::create(client);
                client.set_stake(address, stake, quota)
            }
            ("stakePermillage", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = NodeManageClient::create(client);
                client.stake_permillage(address, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("QuotaManager", Some(m)) => match m.subcommand() {
            ("getBQL", Some(m)) => QuotaManageClient::create(client).get_bql(m.value_of("height")),
            ("getDefaultAQL", Some(m)) => {
                QuotaManageClient::create(client).get_default_aql(m.value_of("height"))
            }
            ("getAccounts", Some(m)) => {
                QuotaManageClient::create(client).get_accounts(m.value_of("height"))
            }
            ("getQuotas", Some(m)) => {
                QuotaManageClient::create(client).get_quotas(m.value_of("height"))
            }
            ("getAQL", Some(m)) => {
                let address = m.value_of("address").unwrap();
                QuotaManageClient::create(client).get_aql(address, m.value_of("height"))
            }
            ("setBQL", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let quota_limit = parse_u256(m.value_of("quota-limit").unwrap())?;
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(client).set_bql(quota_limit, quota)
            }
            ("setDefaultAQL", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let quota_limit = parse_u256(m.value_of("quota-limit").unwrap())?;
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(client).set_default_aql(quota_limit, quota)
            }
            ("setAQL", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let quota_limit = parse_u256(m.value_of("quota-limit").unwrap())?;
                let address = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                QuotaManageClient::create(client).set_aql(address, quota_limit, quota)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Group", Some(m)) => match m.subcommand() {
            ("queryInfo", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(client);
                GroupExt::query_info(&client, address, m.value_of("height"))
            }
            ("queryName", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(client);
                GroupExt::query_name(&client, address, m.value_of("height"))
            }
            ("queryAccounts", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = GroupClient::create(client);
                GroupExt::query_accounts(&client, address, m.value_of("height"))
            }
            ("queryChild", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(client).query_child(address, m.value_of("height"))
            }
            ("queryChildLength", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(client).query_child_length(address, m.value_of("height"))
            }
            ("queryParent", Some(m)) => {
                let address = m.value_of("address").unwrap();
                GroupClient::create(client).query_parent(address, m.value_of("height"))
            }
            ("inGroup", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let account_address = m.value_of("account").unwrap();
                GroupClient::create(client).in_group(address, account_address, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("GroupManagement", Some(m)) => match m.subcommand() {
            ("newGroup", Some(m)) => {
                let encryption = encryption(m, config);
                let origin = m.value_of("origin").unwrap();
                let name = m.value_of("name").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = GroupManageClient::create(client);
                client.new_group(origin, name, accounts, quota)
            }
            ("deleteGroup", Some(m)) => {
                let encryption = encryption(m, config);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = GroupManageClient::create(client);
                client.delete_group(origin, target, quota)
            }
            ("updateGroupName", Some(m)) => {
                let encryption = encryption(m, config);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let name = m.value_of("name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = GroupManageClient::create(client);
                client.update_group_name(origin, target, name, quota)
            }
            ("addAccounts", Some(m)) => {
                let encryption = encryption(m, config);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = GroupManageClient::create(client);
                client.add_accounts(origin, target, accounts, quota)
            }
            ("deleteAccounts", Some(m)) => {
                let encryption = encryption(m, config);
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = GroupManageClient::create(client);
                client.delete_accounts(origin, target, accounts, quota)
            }
            ("checkScope", Some(m)) => {
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let client = GroupManageClient::create(client);
                client.check_scope(origin, target, m.value_of("height"))
            }
            ("queryGroups", Some(m)) => {
                let client = GroupManageClient::create(client);
                client.query_groups(m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Role", Some(m)) => match m.subcommand() {
            ("queryRole", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(client);
                client.query_role(address, m.value_of("height"))
            }
            ("queryName", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(client);
                client.query_name(address, m.value_of("height"))
            }
            ("queryPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(client);
                client.query_permissions(address, m.value_of("height"))
            }
            ("lengthOfPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let client = RoleClient::create(client);
                client.length_of_permissions(address, m.value_of("height"))
            }
            ("inPermissions", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let permission = m.value_of("permission").unwrap();
                let client = RoleClient::create(client);
                client.in_permissions(address, permission, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("RoleManagement", Some(m)) => match m.subcommand() {
            ("newRole", Some(m)) => {
                let encryption = encryption(m, config);
                let name = m.value_of("name").unwrap();
                let permissions = m.value_of("permissions").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::new_role(&mut client, name, permissions, quota)
            }
            ("deleteRole", Some(m)) => {
                let encryption = encryption(m, config);
                let role = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::delete_role(&mut client, role, quota)
            }
            ("updateRoleName", Some(m)) => {
                let encryption = encryption(m, config);
                let role = m.value_of("address").unwrap();
                let name = m.value_of("name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::update_role_name(&mut client, role, name, quota)
            }
            ("addPermissions", Some(m)) => {
                let encryption = encryption(m, config);
                let role = m.value_of("address").unwrap();
                let permissions = m.value_of("permissions").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::add_permissions(&mut client, role, permissions, quota)
            }
            ("deletePermissions", Some(m)) => {
                let encryption = encryption(m, config);
                let role = m.value_of("address").unwrap();
                let permissions = m.value_of("permissions").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::delete_permissions(&mut client, role, permissions, quota)
            }
            ("setRole", Some(m)) => {
                let encryption = encryption(m, config);
                let account = m.value_of("account").unwrap();
                let role = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::set_role(&mut client, account, role, quota)
            }
            ("cancelRole", Some(m)) => {
                let encryption = encryption(m, config);
                let account = m.value_of("account").unwrap();
                let role = m.value_of("address").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::cancel_role(&mut client, account, role, quota)
            }
            ("clearRole", Some(m)) => {
                let encryption = encryption(m, config);
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = RoleManageClient::create(client);
                RoleManagementExt::clear_role(&mut client, account, quota)
            }
            ("queryRoles", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let client = RoleManageClient::create(client);
                RoleManagementExt::query_roles(&client, account, m.value_of("height"))
            }
            ("queryAccounts", Some(m)) => {
                let role = m.value_of("address").unwrap();
                let client = RoleManageClient::create(client);
                RoleManagementExt::query_accounts(&client, role, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Authorization", Some(m)) => match m.subcommand() {
            ("queryPermissions", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let client = AuthorizationClient::create(client);
                AuthorizationExt::query_permissions(&client, account, m.value_of("height"))
            }
            ("queryAccounts", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = AuthorizationClient::create(client);
                AuthorizationExt::query_accounts(&client, permission, m.value_of("height"))
            }
            ("queryAllAccounts", Some(m)) => {
                let client = AuthorizationClient::create(client);
                AuthorizationExt::query_all_accounts(&client, m.value_of("height"))
            }
            ("checkResource", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let contract = m.value_of("contract").unwrap();
                let function_hash = m.value_of("function-hash").unwrap();
                let client = AuthorizationClient::create(client);
                AuthorizationExt::check_resource(
                    &client,
                    account,
                    contract,
                    function_hash,
                    m.value_of("height"),
                )
            }
            ("checkPermission", Some(m)) => {
                let account = m.value_of("account").unwrap();
                let permission = m.value_of("permission").unwrap();
                let client = AuthorizationClient::create(client);
                AuthorizationExt::check_permission(
                    &client,
                    account,
                    permission,
                    m.value_of("height"),
                )
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Permission", Some(m)) => match m.subcommand() {
            ("inPermission", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let contract = m.value_of("contract").unwrap();
                let function_hash = m.value_of("function-hash").unwrap();
                let client = PermissionClient::create(client);
                PermissionExt::in_permission(
                    &client,
                    permission,
                    contract,
                    function_hash,
                    m.value_of("height"),
                )
            }
            ("queryInfo", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(client);
                PermissionExt::query_info(&client, permission, m.value_of("height"))
            }
            ("queryName", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(client);
                PermissionExt::query_name(&client, permission, m.value_of("height"))
            }
            ("queryResource", Some(m)) => {
                let permission = m.value_of("permission").unwrap();
                let client = PermissionClient::create(client);
                PermissionExt::query_resource(&client, permission, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("PermissionManagement", Some(m)) => match m.subcommand() {
            ("newPermission", Some(m)) => {
                let encryption = encryption(m, config);
                let name = m.value_of("name").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::new_permission(
                    &mut client,
                    name,
                    contracts,
                    function_hashes,
                    quota,
                )
            }
            ("deletePermission", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::delete_permission(&mut client, permission, quota)
            }
            ("updatePermissionName", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let name = m.value_of("name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::update_permission_name(
                    &mut client,
                    permission,
                    name,
                    quota,
                )
            }
            ("addResources", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::add_resources(
                    &mut client,
                    permission,
                    contracts,
                    function_hashes,
                    quota,
                )
            }
            ("deleteResources", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let contracts = m.value_of("contracts").unwrap();
                let function_hashes = m.value_of("function-hashes").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::delete_resources(
                    &mut client,
                    permission,
                    contracts,
                    function_hashes,
                    quota,
                )
            }
            ("setAuthorization", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::set_authorization(&mut client, account, permission, quota)
            }
            ("setAuthorizations", Some(m)) => {
                let encryption = encryption(m, config);
                let permissions = m.value_of("permissions").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::set_authorizations(
                    &mut client,
                    account,
                    permissions,
                    quota,
                )
            }
            ("cancelAuthorization", Some(m)) => {
                let encryption = encryption(m, config);
                let permission = m.value_of("permission").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::cancel_authorization(
                    &mut client,
                    account,
                    permission,
                    quota,
                )
            }
            ("cancelAuthorizations", Some(m)) => {
                let encryption = encryption(m, config);
                let permissions = m.value_of("permissions").unwrap();
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::cancel_authorizations(
                    &mut client,
                    account,
                    permissions,
                    quota,
                )
            }
            ("clearAuthorization", Some(m)) => {
                let encryption = encryption(m, config);
                let account = m.value_of("account").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let mut client = PermissionManageClient::create(client);
                PermissionManagementExt::clear_authorization(&mut client, account, quota)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("AdminManagement", Some(m)) => match m.subcommand() {
            ("admin", Some(m)) => AdminClient::create(client).admin(m.value_of("height")),
            ("isAdmin", Some(m)) => {
                let address = m.value_of("address").unwrap();
                AdminClient::create(client).is_admin(address, m.value_of("height"))
            }
            ("update", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let address = m.value_of("address").unwrap();
                AdminClient::create(client).add_admin(address, quota)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("BatchTx", Some(m)) => match m.subcommand() {
            ("multiTxs", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("private-key").unwrap(),
                    encryption,
                )?);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let txs = m.values_of("tx-code").map(Iterator::collect).unwrap();
                BatchTxClient::create(client).multi_transactions(txs, quota)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("SysConfig", Some(m)) => match m.subcommand() {
            ("getChainOwner", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_chain_owner(&client, m.value_of("height"))
            }
            ("getChainId", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_chain_id(&client, m.value_of("height"))
            }
            ("getChainIdV1", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_chain_id_v1(&client, m.value_of("height"))
            }
            ("getDelayBlockNumber", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_delay_block_number(&client, m.value_of("height"))
            }
            ("getFeeBackPlatformCheck", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_feeback_platform_check(&client, m.value_of("height"))
            }
            ("getEconomicalModel", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_economical_model(&client, m.value_of("height"))
            }
            ("getPermissionCheck", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_permission_check(&client, m.value_of("height"))
            }
            ("getQuotaCheck", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_quota_check(&client, m.value_of("height"))
            }
            ("setChainName", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: SysConfigClient<Client> = SysConfigExt::create(client);
                let name = m.value_of("chain-name").unwrap();
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                SysConfigExt::set_chain_name(&mut client, name, quota)
            }
            ("setOperator", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: SysConfigClient<Client> = SysConfigExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let operator = m.value_of("operator").unwrap();
                SysConfigExt::set_operator(&mut client, operator, quota)
            }
            ("setWebsite", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: SysConfigClient<Client> = SysConfigExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let website = m.value_of("website").unwrap();
                SysConfigExt::set_website(&mut client, website, quota)
            }
            ("setBlockInterval", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: SysConfigClient<Client> = SysConfigExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let block_interval = m
                    .value_of("blockInterval")
                    .map(|interval| parse_u256(interval).unwrap())
                    .unwrap();

                SysConfigExt::set_block_interval(&mut client, block_interval, quota)
            }
            ("getCreateContractPermissionCheck", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_create_permission_check(&client, m.value_of("height"))
            }
            ("getSendTxPermissionCheck", Some(m)) => {
                let client: SysConfigClient<Client> = SysConfigExt::create(client);
                SysConfigExt::get_send_permission_check(&client, m.value_of("height"))
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("EmergencyBrake", Some(m)) => match m.subcommand() {
            ("state", Some(m)) => {
                let client: EmergencyBrakeClient<Client> = EmergencyBrakeExt::create(client);
                EmergencyBrakeExt::state(&client, m.value_of("height"))
            }
            ("setState", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: EmergencyBrakeClient<Client> = EmergencyBrakeExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let state = m
                    .value_of("state")
                    .map(|state| state.parse::<bool>().unwrap())
                    .unwrap();
                EmergencyBrakeExt::set_state(&mut client, state, quota)
            }
            _ => return Err(sub_matches.usage().to_owned()),
        },
        ("PriceManager", Some(m)) => match m.subcommand() {
            ("getQuotaPrice", Some(m)) => {
                let client: PriceManagerClient<Client> = PriceManagerExt::create(client);
                PriceManagerExt::price(&client, m.value_of("height"))
            }
            ("setQuotaPrice", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: PriceManagerClient<Client> = PriceManagerExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let price = m
                    .value_of("price")
                    .map(|price| parse_u256(price).unwrap())
                    .unwrap();
                PriceManagerExt::set_price(&mut client, price, quota)
            }
            _ => return Err(sub_matches.usage().to_owned()),
        },
        ("VersionManager", Some(m)) => match m.subcommand() {
            ("getVersion", Some(m)) => {
                let client: VersionManagerClient<Client> = VersionManagerExt::create(client);
                VersionManagerExt::get_version(&client, m.value_of("height"))
            }
            ("setVersion", Some(m)) => {
                let encryption = encryption(m, config);
                client.set_private_key(&parse_privkey(
                    m.value_of("admin-private").unwrap(),
                    encryption,
                )?);
                let mut client: VersionManagerClient<Client> = VersionManagerExt::create(client);
                let quota = m.value_of("quota").map(|quota| parse_u64(quota).unwrap());
                let version = m
                    .value_of("version")
                    .map(|version| parse_u256(version).unwrap())
                    .unwrap();
                VersionManagerExt::set_version(&mut client, version, quota)
            }
            _ => return Err(sub_matches.usage().to_owned()),
        },
        _ => return Err(sub_matches.usage().to_owned()),
    };
    let is_color = !sub_matches.is_present("no-color") && config.color();
    let response = result.map_err(|err| format!("{}", err))?;
    printer.println(&response, is_color);
    set_output(&response, config);
    Ok(())
}
