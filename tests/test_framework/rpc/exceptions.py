"""
test_framework.rpc.exceptions

Custom exceptions for JSONRPC calls.
"""


class JSONRPCError(Exception):
    """A custom exception for JSONRPC calls"""

    def __init__(self, rpc_id: str, code: str, data: str, message: str):
        """Initialize with message, the error code and the caller id"""
        super().__init__(message)
        self.message = message
        self.rpc_id = rpc_id
        self.code = code
        self.data = data

    def __repr__(self):
        """Format the exception repr"""
        return f"{self.message} for request id={self.rpc_id} (data={self.data})"

    def __str__(self):
        """Format the exception str(<exception>)"""
        return self.__repr__()
