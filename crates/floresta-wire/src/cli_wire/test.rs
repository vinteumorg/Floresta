#[cfg(test)]
mod tests {
    use super::*;
    use mockall::{mock, predicate::*};

    // This block defines a mock implemetation of the BTCDClient interface,
    // used to simulate responses from an external Bitcoin RPC Server.
    mock! {
        BTCDClientMock {
            // Define a mock method corresponding to the `getbestblock` function
            // in the BTCDClient interface. This funcion should return a Reesult containing
            // blockchain info.
            fn getbestblock(&self) -> Result<json_types::BlockchainInfo>;
        }
        // Implement the BTCDRpc trait for the mock, ensuring it can replace the real BTCDClient in tests.
        impl BtcdRpc for BTCDClientMock {
            fn getbestblock(&self) -> Result<json_types::BlockchainInfo>;
        }
    }

    #[test]
    fn test_get_height() {
        // Create a new instance of the mock
        let mut mock_rpc = MockBTCDClientMock::new();

        // Configure the mock to expect a call to `getbestblock` exactly once,
        // returning a fixed height of 123 wrapped in the appropriate Result and BlockchainInfo struct.
        mock_rpc.expect_getbestblock().times(1).returning(|| {
            Ok(json_types::BlockchainInfo {
                height: 123,
                ..Default::default()
            })
        });

        // Construct the UtreexodBackend instance using the mocked BTCDClient.
        // This instance will be used to test the `get_height` method.
        let backend = UtreexodBackend {
            rpc: Arc::new(mock_rpc), // Inject the mock into the backend.
            ..Default::default()     // Use default values for other properties of UtreexodBackend.
        };

        // Call get_height and assert the expected result
        assert_eq!(backend.get_height().unwrap(), 123);
    }
}
