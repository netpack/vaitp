import json
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

class Operations:
    PNPublishFileOperation = "PNPublishFileOperation"


class Utils:
    @staticmethod
    def encodeString(s: str) -> str:
        return quote(s)


class Base64Codec:
    @staticmethod
    def encode(data: bytes) -> str:
        import base64
        return base64.b64encode(data).decode('utf-8')


class CryptoModule:
    def encrypt(self, data: str) -> str:
      return data
      

class Config:
    def __init__(self, publishKey: str, subscribeKey: str):
      self.publishKey = publishKey
      self.subscribeKey = subscribeKey
    def getTransactionTimeout(self) -> int:
      return 60


class Modules:
    def __init__(self, config: Config, cryptoModule: Optional[CryptoModule] = None):
      self.config = config
      self.cryptoModule = cryptoModule

def preparePayload(modules: Modules, payload: Dict) -> str:
    stringifiedPayload = json.dumps(payload)
    if modules.cryptoModule:
        encrypted = modules.cryptoModule.encrypt(stringifiedPayload)
        stringifiedPayload = encrypted if isinstance(encrypted, str) else Base64Codec.encode(encrypted.encode('utf-8'))
        stringifiedPayload = json.dumps(stringifiedPayload)
    return stringifiedPayload or ''

class Endpoint:
    @staticmethod
    def getOperation() -> str:
        return Operations.PNPublishFileOperation

    @staticmethod
    def validateParams(_: Any, params: Optional[Dict]) -> Optional[str]:
        if not params or not params.get("channel"):
            return "channel can't be empty"
        if not params or not params.get("fileId"):
            return "file id can't be empty"
        if not params or not params.get("fileName"):
            return "file name can't be empty"
        return None

    @staticmethod
    def getURL(modules: Modules, params: Dict) -> str:
        publishKey = modules.config.publishKey
        subscribeKey = modules.config.subscribeKey
        message = {
            "message": params.get("message"),
            "file": {
                "name": params["fileName"],
                "id": params["fileId"],
            },
        }
        payload = preparePayload(modules, message)
        return f"/v1/files/publish-file/{publishKey}/{subscribeKey}/0/{Utils.encodeString(params['channel'])}/0/{Utils.encodeString(payload)}"

    @staticmethod
    def getRequestTimeout(modules: Modules) -> int:
        return modules.config.getTransactionTimeout()

    @staticmethod
    def isAuthSupported() -> bool:
        return True

    @staticmethod
    def prepareParams(_: Any, params: Dict) -> Dict:
        out_params = {}
        if params.get("ttl"):
            out_params["ttl"] = params["ttl"]
        if "storeInHistory" in params:
             out_params["store"] = '1' if params["storeInHistory"] else '0'
        if "meta" in params and isinstance(params["meta"], dict):
            out_params["meta"] = json.dumps(params["meta"])
        return out_params

    @staticmethod
    def handleResponse(_: Any, response: Dict) -> Dict:
        return {"timetoken": response.get("2")}


endpoint = Endpoint