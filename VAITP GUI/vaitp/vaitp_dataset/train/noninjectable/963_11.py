def __processMessage(modules, message):
    config = modules.get("config")
    crypto = modules.get("crypto")
    if not config or not config.get("cipherKey"):
        return message
    try:
        return crypto.decrypt(message)
    except Exception as e:
        return message


def getOperation():
    from constants.operations import PNFetchMessagesOperation
    return PNFetchMessagesOperation


def validateParams(modules, incomingParams):
    channels = incomingParams.get("channels")
    includeMessageActions = incomingParams.get("includeMessageActions", False)
    config = modules.get("config")
    if not channels or len(channels) == 0:
        return 'Missing channels'
    if not config or not config.get("subscribeKey"):
        return 'Missing Subscribe Key'
    if includeMessageActions and len(channels) > 1:
        raise TypeError('History can return actions data for a single channel only. ' +
                        'Either pass a single channel or disable the includeMessageActions flag.')


def getURL(modules, incomingParams):
    channels = incomingParams.get("channels", [])
    includeMessageActions = incomingParams.get("includeMessageActions", False)
    config = modules.get("config")
    from utils import encodeString
    endpoint = 'history' if not includeMessageActions else 'history-with-actions'
    stringifiedChannels = ','.join(channels) if len(channels) > 0 else ','
    return f"/v3/{endpoint}/sub-key/{config.get('subscribeKey')}/channel/{encodeString(stringifiedChannels)}"


def getRequestTimeout(modules):
    config = modules.get("config")
    return config.getTransactionTimeout()


def isAuthSupported():
    return True


def prepareParams(modules, incomingParams):
    channels = incomingParams.get("channels")
    start = incomingParams.get("start")
    end = incomingParams.get("end")
    includeMessageActions = incomingParams.get("includeMessageActions")
    count = incomingParams.get("count")
    stringifiedTimeToken = incomingParams.get("stringifiedTimeToken", False)
    includeMeta = incomingParams.get("includeMeta", False)
    includeUuid = incomingParams.get("includeUuid")
    includeUUID = incomingParams.get("includeUUID", True)
    includeMessageType = incomingParams.get("includeMessageType", True)

    outgoingParams = {}
    if count:
        outgoingParams["max"] = count
    else:
        outgoingParams["max"] = 25 if (len(channels) > 1 or includeMessageActions) else 100
    if start:
        outgoingParams["start"] = start
    if end:
        outgoingParams["end"] = end
    if stringifiedTimeToken:
        outgoingParams["string_message_token"] = 'true'
    if includeMeta:
        outgoingParams["include_meta"] = 'true'
    if includeUUID and includeUuid is not False:
        outgoingParams["include_uuid"] = 'true'
    if includeMessageType:
        outgoingParams["include_message_type"] = 'true'
    return outgoingParams


def handleResponse(modules, serverResponse):
    response = {
        "channels": {},
    }
    channels = serverResponse.get("channels", {})
    for channelName, messages in channels.items():
        response["channels"][channelName] = []
        for messageEnvelope in messages:
          announce = {}
          announce["channel"] = channelName
          announce["timetoken"] = messageEnvelope.get("timetoken")
          announce["message"] = __processMessage(modules, messageEnvelope.get("message"))
          announce["messageType"] = messageEnvelope.get("message_type")
          announce["uuid"] = messageEnvelope.get("uuid")
          actions = messageEnvelope.get("actions")
          if actions:
              announce["actions"] = actions
              announce["data"] = actions
          meta = messageEnvelope.get("meta")
          if meta:
              announce["meta"] = meta
          response["channels"][channelName].append(announce)
    
    more = serverResponse.get("more")
    if more:
      response["more"] = more
    
    return response
