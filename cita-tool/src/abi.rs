use std::fs::File;

use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, StrictTokenizer, Token, Tokenizer};
use ethabi::{decode, encode, Contract, Function};
use hex::{decode as hex_decode, encode as hex_encode};

use error::ToolError;

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

/// According to the given abi file, encode the function and parameter values
pub fn encode_input(
    path: &str,
    function: &str,
    values: &[String],
    lenient: bool,
) -> Result<String, ToolError> {
    let function = load_function(path, function).map_err(ToolError::Abi)?;

    let params: Vec<_> = function
        .inputs
        .iter()
        .map(|param| param.kind.clone())
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient).map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let result = function
        .encode_input(&tokens)
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;

    Ok(hex_encode(result))
}

/// According to type, encode the value of the parameter
pub fn encode_params(
    types: &[String],
    values: &[String],
    lenient: bool,
) -> Result<String, ToolError> {
    assert_eq!(types.len(), values.len());

    let types: Vec<ParamType> = types
        .iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;

    let params: Vec<_> = types
        .into_iter()
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient).map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let result = encode(&tokens);

    Ok(hex_encode(result))
}

/// According to type, decode the data
pub fn decode_params(types: &[String], data: &str) -> Result<Vec<String>, ToolError> {
    let types: Vec<ParamType> = types
        .iter()
        .map(|s| Reader::read(s))
        .collect::<Result<_, _>>()
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;

    let data = hex_decode(data).map_err(ToolError::Decode)?;

    let tokens = decode(&types, &data).map_err(|e| ToolError::Abi(format!("{}", e)))?;

    assert_eq!(types.len(), tokens.len());

    let result = types
        .iter()
        .zip(tokens.iter())
        .map(|(ty, to)| {
            if to.type_check(&ParamType::Bool) || format!("{}", ty) == "bool[]" {
                format!("{{\"{}\": {}}}", ty, to)
            } else {
                format!("{{\"{}\": \"{}\"}}", ty, to)
            }
        })
        .collect::<Vec<String>>();

    Ok(result)
}
