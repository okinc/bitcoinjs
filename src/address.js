var bs58check = require('bs58check')
var bscript = require('./script')
var networks = require('./networks')
var typeforce = require('typeforce')
var types = require('./types')

function fromBase58Check (address) {
  var payload = bs58check.decode(address)
  if (payload.length < 21) throw new TypeError(address + ' is too short')
  if (payload.length > 21) throw new TypeError(address + ' is too long')

  var version = payload[0]
  var hash = payload.slice(1)

  return { hash: hash, version: version }
}

function fromOutputScript (scriptPubKey, network) {
  network = network || networks.bitcoin

  var outputBuffer = bscript.compile(scriptPubKey)

  if (bscript.isPubKeyHashOutput(scriptPubKey)){
    if (outputBuffer.length > 25) {
      return toBase58Check(outputBuffer.slice(30, 50), network.pubKeyHash)
    }else{
      return toBase58Check(outputBuffer.slice(3, 23), network.pubKeyHash)
    }
    
  } else if (bscript.isScriptHashOutput(scriptPubKey)){
    if (outputBuffer.length > 23) {
      return toBase58Check(outputBuffer.slice(29, 49), network.scriptHash)
    }else{
      return toBase58Check(outputBuffer.slice(2, 22), network.scriptHash)
    }
  }
  
  throw new Error(bscript.toASM(scriptPubKey) + ' has no matching Address')
}

function toBase58Check (hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments)

  var payload = new Buffer(21)
  payload.writeUInt8(version, 0)
  hash.copy(payload, 1)

  return bs58check.encode(payload)
}

function toOutputScript (address, network) {
  network = network || networks.bitcoin

  var decode = fromBase58Check(address)
  if (decode.version === network.pubKeyHash) return bscript.pubKeyHashOutput(decode.hash)
  if (decode.version === network.scriptHash) return bscript.scriptHashOutput(decode.hash)

  throw new Error(address + ' has no matching Script')
}


function toSuperOutputScript (address, superAddress, network) {
  network = network || networks.bitcoin

  var decode = fromBase58Check(address)
  var superdecode = fromBase58Check(superAddress)
  if (decode.version === network.pubKeyHash) return bscript.pubKeyHashSuperOutput(decode.hash, superdecode.hash)
  if (decode.version === network.scriptHash) return bscript.scriptHashSuperOutput(decode.hash, superdecode.hash)

  throw new Error(address + ' has no matching Script')
}


module.exports = {
  fromBase58Check: fromBase58Check,
  fromOutputScript: fromOutputScript,
  toBase58Check: toBase58Check,
  toOutputScript: toOutputScript,
  toSuperOutputScript:toSuperOutputScript
}
