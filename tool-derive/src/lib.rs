#![recursion_limit = "128"]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashSet;
use syn::DeriveInput;

#[proc_macro_derive(ContractExt, attributes(contract))]
pub fn contract(input: TokenStream) -> TokenStream {
    // Parse the string representation
    let input: DeriveInput = syn::parse(input).unwrap();
    let mut trait_name = "".to_string();
    let mut address = "".to_string();
    let mut path = "".to_string();
    for meta_items in input.attrs.iter().filter_map(get_contract_meta_items) {
        for meta_item in meta_items {
            match meta_item {
                // parse #[contract(name = "foo")]
                syn::NestedMeta::Meta(syn::Meta::NameValue(ref m)) if m.ident == "name" => {
                    if let syn::Lit::Str(ref lit) = m.lit {
                        trait_name = lit.value();
                        // println!("{}", lit.value());
                    }
                }
                // parse #[contract(addr = "foo")]
                syn::NestedMeta::Meta(syn::Meta::NameValue(ref m)) if m.ident == "addr" => {
                    if let syn::Lit::Str(ref lit) = m.lit {
                        address = lit.value();
                        // println!("{}", lit.value());
                    }
                }
                // parse #[contract(path = "foo")]
                syn::NestedMeta::Meta(syn::Meta::NameValue(ref m)) if m.ident == "path" => {
                    if let syn::Lit::Str(ref lit) = m.lit {
                        path = lit.value();
                        // println!("{}", lit.value());
                    }
                }
                _ => {}
            }
        }
    }
    if path == "" {
        panic!("path must set");
    }
    if address == "" {
        panic!("contract address must set");
    }
    if trait_name == "" {
        panic!("trait name must set");
    }
    // struct name
    let name = input.ident;
    // parse str to LitStr
    let path = syn::LitStr::new(&path, proc_macro2::Span::call_site());
    // parse str to Ident
    let trait_name = syn::Ident::new(&trait_name.to_string(), proc_macro2::Span::call_site());
    let address = syn::LitStr::new(&address, proc_macro2::Span::call_site());

    let output = if let syn::Data::Struct(data) = input.data {
        let mut field = vec![
            Some(syn::Ident::new("client", proc_macro2::Span::call_site())),
            Some(syn::Ident::new("address", proc_macro2::Span::call_site())),
            Some(syn::Ident::new("contract", proc_macro2::Span::call_site())),
        ]
        .into_iter()
        .collect::<HashSet<Option<syn::Ident>>>();

        if let syn::Fields::Named(ref x) = data.fields {
            if x.named.len() < 3 {
                panic!("Must have 3 more field");
            }
        }

        data.fields.iter().for_each(|i| {
            field.remove(&i.ident);
        });
        if !field.is_empty() {
            panic!("Contract client must have client/address/contract");
        }
        quote!(
            impl<T> #name<T>
                where T: ClientExt<JsonRpcResponse, ToolError>
            {
                /// Create a Contract Client
                pub fn new(client: T, address_str: &str, contract_json: &str) -> Self {
                    let address = Address::from_str(remove_0x(address_str)).unwrap_or_else(|_| Address::default());
                    let contract = Contract::load(contract_json.as_bytes()).unwrap();
                    #name {
                        client,
                        address,
                        contract,
                    }
                }
            }
            impl<T> ContractCall<JsonRpcResponse, ToolError> for #name<T>
                where T: ClientExt<JsonRpcResponse, ToolError>
            {
                fn prepare_call_args(
                    &self,
                    name: &str,
                    values: &[&str],
                    to_addr: Option<Address>,
                ) -> Result<(String, String), ToolError> {
                    let values = values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
                    let code = contract_encode_input(&self.contract, name, values.as_slice(), false)?;
                    let code = format!("0x{}", code);
                    let to_address = to_addr.unwrap_or(self.address);
                    let to_address = format!("{:?}", to_address);
                    Ok((code, to_address))
                }

                fn contract_send_tx(
                    &mut self,
                    name: &str,
                    values: &[&str],
                    quota: Option<u64>,
                    to_addr: Option<Address>,
                ) -> Result<JsonRpcResponse, ToolError> {
                    let (code, to_address) = self.prepare_call_args(name, values, to_addr)?;
                    let tx_options = TransactionOptions::new()
                        .set_code(code.as_str())
                        .set_address(to_address.as_str())
                        .set_quota(quota);
                    self.client.send_raw_transaction(
                        tx_options,
                    )
                }

                fn contract_call(
                    &self,
                    name: &str,
                    values: &[&str],
                    to_addr: Option<Address>,
                    height: Option<&str>,
                ) -> Result<JsonRpcResponse, ToolError> {
                    let (code, to_address) = self.prepare_call_args(name, values, to_addr)?;
                    self.client.call(
                        None,
                        to_address.as_str(),
                        Some(code.as_str()),
                        height.unwrap_or_else(|| "latest"),
                    )
                }
            }
            impl<T> #trait_name<T, JsonRpcResponse, ToolError> for #name<T>
                 where T: ClientExt<JsonRpcResponse, ToolError>,
             {
                    fn create(client: T) -> Self {
                        static ABI: &str = include_str!(#path);
                        static ADDRESS: &str = #address;
                        Self::new(client, ADDRESS, ABI)
                    }
            }
        )
    } else {
        panic!("Only impl to struct")
    };

    // Return the generated impl
    output.into()
}

/// Filter contract attribute like #[contract(foo = bar)]
fn get_contract_meta_items(attr: &syn::Attribute) -> Option<Vec<syn::NestedMeta>> {
    if attr.path.segments.len() == 1 && attr.path.segments[0].ident == "contract" {
        match attr.interpret_meta() {
            Some(syn::Meta::List(ref meta)) => Some(meta.nested.iter().cloned().collect()),
            _ => {
                // TODO: produce an error
                None
            }
        }
    } else {
        None
    }
}
