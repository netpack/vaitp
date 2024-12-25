def __processMessage(modules, message):
    config = modules.get("config")
    crypto = modules.get("crypto")
    if not config or not config.get("cipherKey"):
        return message
    try:
        return crypto.decrypt(message)
    except Exception:
        return message


def getOperation():
    # Assuming operations_1.default.PNHistoryOperation is accessible via a dictionary lookup
    return "PNHistoryOperation" # Placeholder


def validateParams(modules, incomingParams):
    channel = incomingParams.get("channel")
    config = modules.get("config")
    if not channel:
        return 'Missing channel'
    if not config or not config.get("subscribeKey"):
        return 'Missing Subscribe Key'
    return None


def getURL(modules, incomingParams):
    channel = incomingParams.get("channel")
    config = modules.get("config")
    if not channel or not config or not config.get("subscribeKey"):
        return None # Or raise an exception 
    
    # Assuming utils_1.default.encodeString is available via a lookup and replaces .encode("utf-8")
    encoded_channel = channel.encode("utf-8").decode("utf-8")  # Example encode
    return f"/v2/history/sub-key/{config.get('subscribeKey')}/channel/{encoded_channel}"


def getRequestTimeout(modules):
    config = modules.get("config")
    if config and callable(config.get("getTransactionTimeout")):
        return config.get("getTransactionTimeout")()
    return None
    
def isAuthSupported():
    return True


def prepareParams(modules, incomingParams):
    start = incomingParams.get("start")
    end = incomingParams.get("end")
    reverse = incomingParams.get("reverse")
    count = incomingParams.get("count", 100)
    stringifiedTimeToken = incomingParams.get("stringifiedTimeToken", False)
    includeMeta = incomingParams.get("includeMeta", False)

    outgoingParams = {
        "include_token": "true",
        "count": count
    }
    if start:
        outgoingParams["start"] = start
    if end:
        outgoingParams["end"] = end
    if stringifiedTimeToken:
        outgoingParams["string_message_token"] = 'true'
    if reverse is not None:
        outgoingParams["reverse"] = str(reverse)
    if includeMeta:
        outgoingParams["include_meta"] = 'true'
    return outgoingParams


def handleResponse(modules, serverResponse):
    response = {
        "messages": [],
        "startTimeToken": serverResponse[1],
        "endTimeToken": serverResponse[2],
    }
    if isinstance(serverResponse[0], list):
        for serverHistoryItem in serverResponse[0]:
            item = {
                "timetoken": serverHistoryItem.get("timetoken"),
                "entry": __processMessage(modules, serverHistoryItem.get("message")),
            }
            if serverHistoryItem.get("meta"):
                item["meta"] = serverHistoryItem.get("meta")
            response["messages"].append(item)
    return response