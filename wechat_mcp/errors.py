class WeChatMCPError(Exception):
    """Base error returned to MCP clients as a readable message."""


class UnsupportedPlatform(WeChatMCPError):
    pass


class DataNotFound(WeChatMCPError):
    pass


class KeyNotFound(WeChatMCPError):
    pass


class KeyInvalid(WeChatMCPError):
    pass


class DecryptError(WeChatMCPError):
    pass


class ContactNotFound(WeChatMCPError):
    pass


class ContactAmbiguous(WeChatMCPError):
    pass
