use std::fs::File;

use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, StrictTokenizer, Token, Tokenizer};
use ethabi::{encode, Contract, Function};
use hex::ToHex;

fn load_function(path: &str, function: &str) -> Result<Function, String> {
    let file = File::open(path).map_err(|e| format!("{}", e))?;
    let contract = Contract::load(file).map_err(|e| format!("{}", e))?;
    let function = contract
        .function(function)
        .map_err(|e| format!("{}", e))?
        .clone();
    Ok(function)
}

fn parse_tokens(params: &[(ParamType, &str)], lenient: bool) -> Result<Vec<Token>, String> {
    params
        .iter()
        .map(|&(ref param, value)| match lenient {
            true => LenientTokenizer::tokenize(param, value),
            false => StrictTokenizer::tokenize(param, value),
        })
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}", e))
}

pub fn encode_input(
    path: &str,
    function: &str,
    values: &[String],
    lenient: bool,
) -> Result<String, String> {
    let function = load_function(path, function)?;

    let params: Vec<_> = function
        .inputs
        .iter()
        .map(|param| param.kind.clone())
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient).map_err(|e| format!("{}", e))?;
    let result = function
        .encode_input(&tokens)
        .map_err(|e| format!("{}", e))?;

    Ok(result.to_hex())
}

pub fn encode_params(types: &[String], values: &[String], lenient: bool) -> Result<String, String> {
    assert_eq!(types.len(), values.len());

    let types: Vec<ParamType> = types
        .iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}", e))?;

    let params: Vec<_> = types
        .into_iter()
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient).map_err(|e| format!("{}", e))?;
    let result = encode(&tokens);

    Ok(result.to_hex())
}
