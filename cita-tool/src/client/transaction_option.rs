use types::U256;

/// Transaction parameter option
#[derive(Clone, Copy, Debug)]
pub struct TransactionOptions<'a> {
    code: &'a str,
    address: &'a str,
    current_height: Option<u64>,
    quota: Option<u64>,
    value: Option<U256>,
    version: Option<u32>,
}

impl<'a> TransactionOptions<'a> {
    /// Default option
    pub fn new() -> Self {
        TransactionOptions {
            code: "0x",
            address: "0x",
            current_height: None,
            quota: None,
            value: None,
            version: None,
        }
    }

    /// Set code. Transaction content, default is "0x"
    pub fn set_code(mut self, code: &'a str) -> Self {
        self.code = code;
        self
    }

    /// Get code
    pub fn code(&self) -> &str {
        self.code
    }

    /// Set address. Destination address (account or contract address),
    /// default is "0x", which creates the contract
    pub fn set_address(mut self, address: &'a str) -> Self {
        self.address = address;
        self
    }

    /// Get address
    pub fn address(&self) -> &str {
        self.address
    }

    /// Set current height. Used to set until_block.
    /// Set the current chain height, the default is None,
    /// automatically query before the transaction to get the current chain height
    pub fn set_current_height(mut self, height: Option<u64>) -> Self {
        self.current_height = height;
        self
    }

    /// Get current height
    pub fn current_height(&self) -> Option<u64> {
        self.current_height
    }

    /// Set quota. Transaction consumption quota limit
    pub fn set_quota(mut self, quota: Option<u64>) -> Self {
        self.quota = quota;
        self
    }

    /// Get quota
    pub fn quota(&self) -> Option<u64> {
        self.quota
    }

    /// Set value. Transaction transfer amount
    pub fn set_value(mut self, value: Option<U256>) -> Self {
        self.value = value;
        self
    }

    /// Get value
    pub fn value(&self) -> Option<U256> {
        self.value
    }

    /// Set version.
    pub fn set_version(mut self, version: Option<u32>) -> Self {
        self.version = version;
        self
    }

    /// Get version
    pub fn version(&self) -> Option<u32> {
        self.version
    }

    /// Restore initialization status
    pub fn clear(&mut self) {
        self.value = None;
        self.quota = None;
        self.current_height = None;
        self.address = "0x";
        self.code = "0x";
        self.version = None
    }
}

impl Default for TransactionOptions<'static> {
    fn default() -> Self {
        TransactionOptions::new()
    }
}
