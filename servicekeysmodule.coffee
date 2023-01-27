############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("servicekeysmodule")
#endregion

############################################################
import * as cachedData from "cached-persistentstate"
cachedData.initialize()
import * as secUtl from "secret-manager-crypto-utils"

import * as validatableStamp from "validatabletimestamp"


############################################################
serviceState = null
godKeyHex = null

############################################################
setReady = null
ready = new Promise (resolve) -> setReady = resolve 

############################################################
export initialize = ->
    log "initialize"
    serviceState = cachedData.load("serviceState")
    # olog serviceState
    
    if !serviceState.secretKeyHex
        kp = await secUtl.createKeyPairHex()
        serviceState.secretKeyHex = kp.secretKeyHex
        serviceState.publicKeyHex = kp.publicKeyHex
        cachedData.save("serviceState")
    
    # olog serviceState
    setReady(true)
    return

############################################################
export isNotGod = (keyHex) -> return keyHex != godKeyHex

############################################################
export getPublicKeyHex = -> serviceState.publicKeyHex

############################################################
export sign = (content) ->
    await ready
    keyHex = serviceState.secretKeyHex
    signatureHex = await secUtl.createSignatureHex(content, keyHex)
    return signatureHex

############################################################
export verify = (sigHex, content) ->
    await ready
    pubHex = serviceState.publicKeyHex
    result = await secUtl.verifyHex(sigHex, pubHex, content)
    return result

############################################################
export getSignedNodeId = ->
    log "getSignedNodeId"
    await ready
    log "we are ready!"
    result = {}
    result.serverNodeId = serviceState.publicKeyHex
    result.timestamp = validatableStamp.create()
    content = JSON.stringify(result)
    result.signature = await sign(content)
    return result

############################################################
export getEntropySeed = (clientId) ->
    log "getEntropySeed"
    context = "lenny test context"+validatableStamp.create()
    seedHex = await secUtl.createSharedSecretHashHex(serviceState.secretKeyHex, clientId, context)
    return seedHex

############################################################
export encrypt = (data) ->
    salt = await secUtl.createRandomLengthSalt()
    content = salt + JSON.stringify(data)
    return await secUtl.asymmetricEncryptHex(content, serviceState.publicKeyHex)

export decrypt = (secretsObj) ->
    content = await secUtl.asymmetricDecryptHex(secretsObj, serviceState.secretKeyHex)
    return JSON.parse(secUtl.removeSalt(content))



