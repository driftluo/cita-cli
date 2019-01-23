use std::fs::File;
use std::io::Read;

use crate::LowerHex;
use ethabi::param_type::{ParamType, Reader};
use ethabi::token::{LenientTokenizer, StrictTokenizer, Token, Tokenizer};
use ethabi::{decode, encode, Contract, Hash};
use hex::{decode as hex_decode, encode as hex_encode};
use types::U256;

use crate::error::ToolError;

pub fn parse_tokens(params: &[(ParamType, &str)], lenient: bool) -> Result<Vec<Token>, ToolError> {
    params
        .iter()
        .map(|&(ref param, value)| {
            if lenient {
                let type_name = format!("{}", param);
                if type_name.starts_with("uint") && type_name.find(']').is_none() {
                    let y = U256::from_dec_str(value)
                        .map_err(|_| "Can't parse into u256")?
                        .completed_lower_hex();
                    StrictTokenizer::tokenize(param, &y)
                } else if type_name.starts_with("int") && type_name.find(']').is_none() {
                    let x = if value.starts_with('-') {
                        let x = (!U256::from_dec_str(&value[1..])
                            .map_err(|_| "Can't parse into u256")?
                            + U256::from(1))
                        .lower_hex();
                        format!("{:f>64}", x)
                    } else {
                        U256::from_dec_str(value)
                            .map_err(|_| "Can't parse into u256")?
                            .completed_lower_hex()
                    };
                    StrictTokenizer::tokenize(param, &x)
                } else {
                    LenientTokenizer::tokenize(param, value)
                }
            } else {
                StrictTokenizer::tokenize(param, value)
            }
        })
        .collect::<Result<_, _>>()
        .map_err(|e| ToolError::Abi(e.to_string()))
}

/// According to the contract, encode the function and parameter values
pub fn contract_encode_input(
    contract: &Contract,
    function: &str,
    values: &[String],
    lenient: bool,
) -> Result<String, ToolError> {
    let function = contract
        .function(function)
        .map_err(|e| ToolError::Abi(e.to_string()))?
        .clone();
    let params: Vec<_> = function
        .inputs
        .iter()
        .map(|param| param.kind.clone())
        .zip(values.iter().map(|v| v as &str))
        .collect();

    let tokens = parse_tokens(&params, lenient)?;
    let result = function
        .encode_input(&tokens)
        .map_err(|e| ToolError::Abi(e.to_string()))?;

    Ok(hex_encode(result))
}

/// According to the contract, encode the constructor and parameter values
pub fn constructor_encode_input(
    contract: &Contract,
    code: &str,
    values: &[String],
    lenient: bool,
) -> Result<String, ToolError> {
    match contract.constructor {
        Some(ref constructor) => {
            let params: Vec<_> = constructor
                .inputs
                .iter()
                .map(|param| param.kind.clone())
                .zip(values.iter().map(|v| v as &str))
                .collect();
            let tokens = parse_tokens(&params, lenient)?;
            Ok(format!(
                "{}{}",
                code,
                hex_encode(
                    constructor
                        .encode_input(Vec::new(), &tokens)
                        .map_err(|e| ToolError::Abi(e.to_string()))?,
                )
            ))
        }
        None => Err(ToolError::Abi("No constructor on abi".to_string())),
    }
}

/// According to the given abi file, encode the function and parameter values
pub fn encode_input(
    path: Option<&str>,
    abi: Option<&str>,
    function: &str,
    values: &[String],
    lenient: bool,
    constructor: bool,
) -> Result<String, ToolError> {
    let contract =
        Contract::load(get_abi(path, abi)?).map_err(|e| ToolError::Abi(format!("{}", e)))?;
    if constructor {
        constructor_encode_input(&contract, function, values, lenient)
    } else {
        contract_encode_input(&contract, function, values, lenient)
    }
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

    let tokens = parse_tokens(&params, lenient)?;
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

/// According to the given abi file, decode the data
pub fn decode_input(
    path: Option<&str>,
    abi: Option<&str>,
    function: &str,
    data: &str,
) -> Result<Vec<String>, ToolError> {
    let contract =
        Contract::load(get_abi(path, abi)?).map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let function = contract
        .function(function)
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let tokens = function
        .decode_output(data.as_bytes())
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let types = function.outputs.iter().map(|ref param| &param.kind);

    assert_eq!(types.len(), tokens.len());

    let result = types
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

/// According to the given abi file, decode the topic
pub fn decode_logs(
    path: Option<&str>,
    abi: Option<&str>,
    event: &str,
    topics: &[String],
    data: &str,
) -> Result<Vec<String>, ToolError> {
    let contract =
        Contract::load(get_abi(path, abi)?).map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let event = contract
        .event(event)
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;

    let topics: Vec<Hash> = topics
        .iter()
        .map(|t| t.parse())
        .collect::<Result<_, _>>()
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;
    let data = hex_decode(data).map_err(ToolError::Decode)?;
    let decoded = event
        .parse_log((topics, data).into())
        .map_err(|e| ToolError::Abi(format!("{}", e)))?;

    let result = decoded
        .params
        .into_iter()
        .map(|log_param| format!("{{\"{}\": \"{}\"}}", log_param.name, log_param.value))
        .collect::<Vec<String>>();

    Ok(result)
}

fn get_abi(path: Option<&str>, abi: Option<&str>) -> Result<Box<dyn Read>, ToolError> {
    match abi {
        Some(code) => Ok(Box::new(::std::io::Cursor::new(code.to_owned()))),
        None => {
            let file = match path {
                Some(path) => File::open(path).map_err(|e| ToolError::Abi(format!("{}", e)))?,
                None => return Err(ToolError::Abi("No input abi".to_string())),
            };
            Ok(Box::new(file))
        }
    }
}

#[cfg(test)]
mod test {
    use super::encode_params;

    #[test]
    fn test_encode() {
        let a = encode_params(&["int".to_string()], &["-100".to_string()], true).unwrap();
        assert_eq!(
            a,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9c".to_string()
        );

        let b = encode_params(
            &["int".to_string()],
            &["-99999999999999999999999999999999999999999999999999999999999999999999".to_string()],
            true,
        )
        .unwrap();
        assert_eq!(
            b,
            "fffffffc4a717738acec1362cd61555e7046d08adea4e8f00000000000000001".to_string()
        );

        let c = encode_params(&["uint".to_string()], &["100".to_string()], true).unwrap();
        assert_eq!(
            c,
            "0000000000000000000000000000000000000000000000000000000000000064".to_string()
        );

        let d = encode_params(
            &["uint".to_string()],
            &["99999999999999999999999999999999999999999999999999999999999999999999".to_string()],
            true,
        )
        .unwrap();
        assert_eq!(
            d,
            "00000003b58e88c75313ec9d329eaaa18fb92f75215b170fffffffffffffffff".to_string()
        );
    }
}
