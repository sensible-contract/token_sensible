const {
  bsv,
  buildContractClass,
  getPreimage,
  toHex,
  SigHashPreimage,
  signTx,
  PubKey,
  Sig,
  Bytes,
  Ripemd160,
} = require('scryptlib');

const {
    loadDesc,
    compileContract
} = require('../helper');


const TokenProto = require('./tokenProto')

const TokenUtil = module.exports

TokenUtil.RABIN_SIG_LEN = 1024

const genesisFlag = Buffer.from('01', 'hex')
const nonGenesisFlag = Buffer.from('00', 'hex')
const tokenType = Buffer.alloc(4, 0)
tokenType.writeUInt32LE(1)
const PROTO_FLAG = Buffer.from('oraclesv')
// MSB of the sighash  due to lower S policy
const MSB_THRESHOLD = 0x7E

const Genesis = buildContractClass(loadDesc('tokenGenesis_desc.json'))
const Token = buildContractClass(loadDesc('token_desc.json'))
//const Genesis = buildContractClass(compileContract('tokenGenesis.scrypt'))
//const Token = buildContractClass(compileContract('tokenBtp.scrypt'))
const RouteCheck = buildContractClass(loadDesc('tokenRouteCheck_desc.json'))
const UnlockContractCheck = buildContractClass(loadDesc('tokenUnlockContractCheck_desc.json'))

let genesisContract
let routeCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash

TokenUtil.getAmountBuf = function(amount) {
  const buf = Buffer.alloc(8, 0)
  buf.writeBigInt64LE(BigInt(amount))
  return buf
}

TokenUtil.getTxIdBuf = function(txid) {
  const buf = Buffer.from(txid, 'hex').reverse()
  return buf
}

TokenUtil.getIndexBuf = function(index) {
  const buf = Buffer.alloc(4, 0)
  buf.writeUInt32LE(index)
  return buf
}

TokenUtil.getScriptHashBuf = function(scriptBuf) {
  const buf = Buffer.from(bsv.crypto.Hash.sha256ripemd160(scriptBuf))
  return buf
}

TokenUtil.initContractHash = function(rabinPubKeyArray) {
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  let code = routeCheckCode.lockingScript.toBuffer()
  const routeCheckCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  routeCheckCodeHashArray = [routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash]

  const unlockContract = new UnlockContractCheck(rabinPubKeyArray)
  code = unlockContract.lockingScript.toBuffer()
  const unlockContractCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]

}

/** 
 * create genesis contract utxo
 * @function createGenesis
 * @param inputTxId {string} the input utxo txid
 * @param inputTxIndex {int} the input utxo output index
 * @param inputScript {Object} bsv.Script, the input utxo locking script
 * @param inputAmount {int} the input utxo satoshis
 * @param inputPrivKey {Object} bsv.PrivateKey, the input utxo unlocking key 
 * @param fee {int} the tx fee
 * @param issuerPubKey {Object} bsv.PublicKey, issuer public key used to unlocking genesis contract
 * @param rabinPubKeyArray {BigInt[]} rabin pubkey array
 * @param tokenName {Buffer} the token name
 * @param tokenSymbol {Buffer} the token symbol
 * @param genesisAmount {int} the genesis contract utxo output satoshis
 * @param changeAddress {bsv.Address} the change address
 * @param decimalNum {number} the token amount decimal number
*/
TokenUtil.createGenesis = function(
  inputTxId,
  inputTxIndex,
  inputScript,
  inputAmount,
  inputPrivKey, 
  fee, 
  issuerPubKey,
  rabinPubKeyArray,
  tokenName,
  tokenSymbol,
  genesisAmount,
  changeAddress,
  decimalNum,
  ) {
  const decimalBuf = Buffer.alloc(1, 0)
  decimalBuf.writeUInt8(decimalNum)
  const genesis = new Genesis(new PubKey(toHex(issuerPubKey)), rabinPubKeyArray)
  console.log('genesis create args:', toHex(issuerPubKey), tokenName.toString('hex'), decimalNum)
  const oracleData = Buffer.concat([
    tokenName,
    tokenSymbol,
    genesisFlag, 
    decimalBuf,
    Buffer.alloc(20, 0), // address
    Buffer.alloc(8, 0), // token value
    Buffer.alloc(36, 0), // tokenID
    tokenType, // type
    PROTO_FLAG
  ])
  console.log('oracleData:', oracleData.toString('hex'))
  genesis.setDataPart(oracleData.toString('hex'))
  console.log('genesis data part:', oracleData.toString('hex'))

  genesisContract = genesis

  const changeAmount = inputAmount - genesisAmount - fee
  const genesisScript = genesis.lockingScript
  //console.log('genesisScript:', genesisScript.toHex())

  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
    output: new bsv.Transaction.Output({
      script: inputScript,
      satoshis: inputAmount
    }),
    prevTxId: inputTxId,
    outputIndex: inputTxIndex,
    script: bsv.Script.empty()
  }))

  tx.addOutput(new bsv.Transaction.Output({
    script: genesisScript,
    satoshis: genesisAmount,
  }))

  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(changeAddress),
    satoshis: changeAmount,
  }))

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const hashData = bsv.crypto.Hash.sha256ripemd160(inputPrivKey.publicKey.toBuffer())
  const sig = tx.inputs[0].getSignatures(tx, inputPrivKey, 0, sigtype, hashData)
  tx.inputs[0].addSignature(tx, sig[0])

  return tx
}

/** 
 * create token contract from genesis contract utxo
 * @function createToken
 * @param genesisScript {Object} bsv.Script, the genesis contract locking script
 * @param tokenValue {number} the token value want to create
 * @param address {Object} bsv.Address, the token create address
 * @param inputAmount {number} the genesis utxo satoshis
 * @param genesisTxId {string} the genesis utxo id
 * @param genesisTxOutputIndex {number} the genesis utxo output index
 * @param outputSatoshis {number} the token output satoshis
 * @param issuerPrivKey {Object} bsv.PrivateKey, the issuer private key to unlock genesis tx
 * @param rabinPubKeyArray {int[]} rabin pubkey array
 * @param decimalNum {int} token amount decimal num
 * @param bsvInputTxId {string} the input utxo txid
 * @param bsvInputTxIndex {int} the input utxo output index
 * @param bsvInputScript {Object} bsv.Script, the input utxo locking script
 * @param bsvInputAmount {int} the input utxo satoshis
 * @param bsvInputPrivKey {Object} bsv.PrivateKey, the input utxo unlocking key 
 * @param rabinMsg {Buffer} rabin msg of genesis input
 * @param rabinPaddingArray {bytes[]} rabin verify padding of each rabin pubkey
 * @param rabinSigArray {int[]} rabin signature of each rabin pubkey
 * @param changeAddress {Object} bsv.Address, the change address
 * @param fee {int} the tx cost fee
*/
TokenUtil.createToken = function(
  genesisScript, 
  tokenValue,  
  address, 
  inputAmount,
  genesisTxId,
  genesisTxOutputIndex,
  outputSatoshis,
  issuerPrivKey,
  rabinPubKeyArray,
  decimalNum,
  bsvInputTxId,
  bsvInputTxIndex,
  bsvInputScript,
  bsvInputAmount,
  bsvInputPrivKey,
  rabinMsg,
  rabinPaddingArray,
  rabinSigArray,
  changeAddress,
  fee
  ) {

  const scriptBuffer = genesisScript.toBuffer()
  const tokenName = TokenProto.getTokenName(scriptBuffer)
  const tokenSymbol = TokenProto.getTokenSymbol(scriptBuffer)

  const indexBuf = Buffer.alloc(4, 0)
  indexBuf.writeUInt32LE(genesisTxOutputIndex)
  let tokenID = TokenProto.getTokenID(scriptBuffer)
  let isFirstGenesis = false
  if (tokenID.compare(Buffer.alloc(36, 0)) === 0) {
    isFirstGenesis = true
    tokenID = Buffer.concat([
      Buffer.from(genesisTxId, 'hex').reverse(),
      indexBuf,
    ])
    const newScriptBuf = TokenProto.getNewGenesisScript(scriptBuffer, tokenID)
    genesisHash = bsv.crypto.Hash.sha256ripemd160(newScriptBuf)
  }
  else {
    genesisHash = bsv.crypto.Hash.sha256ripemd160(scriptBuffer)
  }

  const tokenContract = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash.toString('hex')))

  const decimalBuf = Buffer.alloc(1, 0)
  decimalBuf.writeUInt8(decimalNum)
  const buffValue = Buffer.alloc(8, 0)
  buffValue.writeBigUInt64LE(BigInt(tokenValue))
  const oracleData = Buffer.concat([
    tokenName,
    tokenSymbol,
    nonGenesisFlag, // genesis flag
    decimalBuf,
    address.hashBuffer, // address
    buffValue, // token value
    tokenID, // script code hash
    tokenType, // type
    PROTO_FLAG
  ])
  tokenContract.setDataPart(oracleData.toString('hex'))

  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    output: new bsv.Transaction.Output({
      script: genesisScript,
      satoshis: inputAmount,
    }),
    prevTxId: genesisTxId,
    outputIndex: genesisTxOutputIndex,
    script: bsv.Script.empty(), // placeholder
  }))

  tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
    output: new bsv.Transaction.Output({
      script: bsvInputScript,
      satoshis: bsvInputAmount
    }),
    prevTxId: bsvInputTxId,
    outputIndex: bsvInputTxIndex,
    script: bsv.Script.empty()
  }))

  const genesisOutSatoshis = outputSatoshis
  let lockingScript = bsv.Script.fromBuffer(TokenProto.getNewGenesisScript(genesisScript.toBuffer(), tokenID))
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: genesisOutSatoshis,
  }))

  let tokenScript = tokenContract.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: tokenScript,
    satoshis: outputSatoshis,
  }))

  const changeSatoshis = inputAmount + bsvInputAmount - outputSatoshis * 2 - fee
  if (changeSatoshis > 0) {
    tx.addOutput(new bsv.Transaction.Output({
      script: bsv.Script.buildPublicKeyHashOut(changeAddress),
      satoshis: changeSatoshis,
    }))
  }

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, genesisScript.toASM(), inputAmount, inputIndex=genesisTxOutputIndex, sighashType=sigtype)
  //console.log("preimage args:", inputAmount, genesisTxOutputIndex, sigtype, genesisScript.toBuffer().toString('hex'))
  let sig = signTx(tx, issuerPrivKey, genesisScript.toASM(), inputAmount, inputIndex=genesisTxOutputIndex, sighashType=sigtype)
  //console.log('createToken: sig ', new bsv.crypto.Signature.fromTxFormat(sig))

  // TODO: get genesis from the script code
  const issuerPubKey = issuerPrivKey.publicKey
  //console.log('genesis args:', toHex(issuerPubKey), tokenName.toString('hex'), decimalNum)
  const unlockingScript = genesisContract.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Sig(toHex(sig)),
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      genesisOutSatoshis,
      new Bytes(tokenScript.toHex()),
      outputSatoshis,
      new Ripemd160(changeAddress.hashBuffer.toString('hex')),
      changeSatoshis
  ).toScript()

  //console.log('genesis unlocking args:', toHex(preimage), toHex(sig), lockingScript.toHex(), outputSatoshis)

  tx.inputs[0].setScript(unlockingScript)

  const hashData = bsv.crypto.Hash.sha256ripemd160(bsvInputPrivKey.publicKey.toBuffer())
  sig = tx.inputs[1].getSignatures(tx, bsvInputPrivKey, 1, sigtype, hashData)
  tx.inputs[1].addSignature(tx, sig[0])

  //console.log('creatToken:', tx.verify(), tx.serialize())

  return tx
}

/** 
 * create routeCheckAmount contract utxo
 * @function createRouteCheckTx
 * @param inputTxId {string} the input bsv utxo txid
 * @param inputTxIndex {int} the input bsv utxo output index
 * @param inputScript {Object} bsv.Script, the input bsv utxo locking script
 * @param inputAmount {int} the input bsv utxo satoshis
 * @param inputPrivKey {Object} bsv.PrivateKey, the input bsv utxo unlocking key 
 * @param outputSatoshis {int} the routeCheckAmount contract utxo output satoshis
 * @param fee {int} the tx fee
 * @param tokenOutputArray {object[]} the token output array
 * @param rabinPubKeyArray {BigInt[]} rabin pubkey array
 * @param tokenID {Buffer} the tokenID
 * @param tokenCodeHash {Buffer} the token contract code hash
*/
TokenUtil.createRouteCheckTx = function(
  inputTxId, 
  inputTxIndex,
  inputAmount,
  inputScript,
  inputPrivKey,
  changeAddress,
  outputSatoshis,
  fee,
  tokenOutputArray,
  rabinPubKeyArray,
  tokenID,
  tokenCodeHash
  ) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
    output: new bsv.Transaction.Output({
      script: inputScript,
      satoshis: inputAmount
    }),
    prevTxId: inputTxId,
    outputIndex: inputTxIndex,
    script: bsv.Script.empty()
  }))

  const nReceiverBuf = Buffer.alloc(1, 0)
  nReceiverBuf.writeUInt8(tokenOutputArray.length)
  let recervierArray = Buffer.alloc(0, 0)
  let receiverTokenAmountArray = Buffer.alloc(0, 0)
  for (let i =0; i < tokenOutputArray.length; i++) {
    const item = tokenOutputArray[i]
    recervierArray = Buffer.concat([recervierArray, item.address.hashBuffer])
    const amountBuf = TokenUtil.getAmountBuf(item.tokenAmount)
    receiverTokenAmountArray = Buffer.concat([receiverTokenAmountArray, amountBuf])
  }

  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  const data = Buffer.concat([
    receiverTokenAmountArray,
    recervierArray,
    nReceiverBuf,
    tokenCodeHash,
    tokenID,
  ])
  routeCheckCode.setDataPart(data.toString('hex'))
  let checkScript = routeCheckCode.lockingScript

  tx.addOutput(new bsv.Transaction.Output({
    script: checkScript,
    satoshis: outputSatoshis,
  }))

  //console.log('script tx info:', outputSatoshis, data.toString('hex'))

  const changeAmount = inputAmount - fee - outputSatoshis
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(changeAddress),
    satoshis: changeAmount,
  }))

  const hashData = bsv.crypto.Hash.sha256ripemd160(inputPrivKey.publicKey.toBuffer())
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const sig = tx.inputs[0].getSignatures(tx, inputPrivKey, 0, sigtype, hashData)
  tx.inputs[0].addSignature(tx, sig[0])

  return tx
}

/** 
 * create tx from token transfer
 * @function createTokenTransfer
 * @param scriptTx {Object} bsv.Transaction, routeCheckAmount contract tx
 * @param tokenInputArray {Array of token input data} token input params, input data: {lockingScript: {bsv.Script}, satoshis: {number}, txId: {hex string}, outputIndex: {number}}
 * @param satoshiInputArray {object[]} bsv input params, the input data format is same as token input data
 * @param rabinPubKeyArray {BigInt[]} rabin public key array
 * @param checkRabinMsgArray {Buffer} concat rabin msg of each token input
 * @param checkRabinPaddingArray {Buffer} concat rabin verify padding of each token input
 * @param checkRabinSignArray {Buffer} concat rabin signature of each token input
 * @param senderPrivKeyArray {object[]} Array of bsv.PrivateKey, the input token unlocking private keys
 * @param satoshiInputPrivKeyArray {object[]} Array of bsv.PrivateKey, the common bsv input unlocking private keys
 * @param tokenOutputArray {object[]} token output params, token output data: {address: {bsv.Address}, tokenAmount: {number}, satoshis: {number}}
 * @param changeSatoshis {number} change output satoshis
 * @param changeAddress {object} bsv.Address, change output address
 * @param tokenRabinMsg {Buffer} rabin msg for token input
 * @param tokenRabinPaddingArray {Buffer} concat rabin verify padding of each rabin pubkey
 * @param tokenRabinSignArray {Buffer} concat rabin signature of each rabin pubkey
 * @param prevPrevTokenAddress {object} bsv.Address, used for rabin msg verify 
 * @param prevPrevTokenAmount {int} used for rabin msg verify 
*/
TokenUtil.createTokenTransfer = function(
  scriptTx,
  tokenInputArray,
  satoshiInputArray,
  rabinPubKeyArray,
  checkRabinMsgArray,
  checkRabinPaddingArray,
  checkRabinSigArray,
  senderPrivKeyArray,
  satoshiInputPrivKeyArray, 
  tokenOutputArray,
  changeSatoshis, 
  changeAddress, 
  tokenRabinMsg,
  tokenRabinPaddingArray,
  tokenRabinSigArray,
  prevPrevTokenAddress,
  prevPrevTokenAmount
) {
  const tx = new bsv.Transaction()

  let prevouts = Buffer.alloc(0)
  const tokenInputLen = tokenInputArray.length
  let inputTokenScript
  let inputTokenAmountArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)
  for (let i = 0; i < tokenInputLen; i++) {
    const tokenInput = tokenInputArray[i]
    const tokenScript = tokenInput.lockingScript
    inputTokenScript = tokenScript
    const tokenScriptBuf = tokenScript.toBuffer()
    const inputSatoshis = tokenInput.satoshis
    const txId = tokenInput.txId
    const outputIndex = tokenInput.outputIndex
    // token contract input
    tx.addInput(new bsv.Transaction.Input({
        output: new bsv.Transaction.Output({
          script: tokenScript,
          satoshis: inputSatoshis
        }),
        prevTxId: txId,
        outputIndex: outputIndex,
        script: bsv.Script.empty()
    }))

    inputTokenAddressArray = Buffer.concat([
      inputTokenAddressArray,
      TokenProto.getTokenAddress(tokenScriptBuf)
    ])
    const amountBuf = Buffer.alloc(8, 0)
    amountBuf.writeBigUInt64LE(BigInt(TokenProto.getTokenAmount(tokenScriptBuf)))
    inputTokenAmountArray = Buffer.concat([
      inputTokenAmountArray,
      amountBuf,
    ])

    // add outputpoint to prevouts
    const indexBuf = TokenUtil.getIndexBuf(outputIndex)
    const txidBuf = TokenUtil.getTxIdBuf(txId)

    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])
  }

  for (let i = 0; i < satoshiInputArray.length; i++) {
    const satoshiInput = satoshiInputArray[i]
    const lockingScript = satoshiInput.lockingScript
    const inputSatoshis = satoshiInput.satoshis
    const txId = satoshiInput.txId
    const outputIndex = satoshiInput.outputIndex
    // bsv input to provide fee
    tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
      output: new bsv.Transaction.Output({
        script: lockingScript,
        satoshis: inputSatoshis
      }),
      prevTxId: txId,
      outputIndex: outputIndex,
      script: bsv.Script.empty()
    }))

    // add outputpoint to prevouts
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(outputIndex)
    const txidBuf = Buffer.from([...Buffer.from(txId, 'hex')].reverse())
    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])
  }

  // add scriptTx
  tx.addInput(new bsv.Transaction.Input({
      output: new bsv.Transaction.Output({
        script: scriptTx.outputs[0].script,
        satoshis: scriptTx.outputs[0].satoshis
      }),
      prevTxId: scriptTx.id,
      outputIndex: 0,
      script: bsv.Script.empty()
  }))
  let indexBuf = Buffer.alloc(4, 0)
  prevouts = Buffer.concat([
    prevouts,
    Buffer.from(scriptTx.id, 'hex').reverse(),
    indexBuf,
  ])

  let recervierArray = Buffer.alloc(0)
  let receiverTokenAmountArray = Buffer.alloc(0)
  let outputSatoshiArray = Buffer.alloc(0)
  const tokenOutputLen = tokenOutputArray.length
  for (let i = 0; i < tokenOutputLen; i++) {
    const tokenOutput = tokenOutputArray[i]
    const address = tokenOutput.address
    const outputTokenAmount = tokenOutput.tokenAmount
    const outputSatoshis = tokenOutput.satoshis
    const lockingScriptBuf = TokenProto.getNewTokenScript(inputTokenScript.toBuffer(), address.hashBuffer, outputTokenAmount) 
    tx.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.fromBuffer(lockingScriptBuf),
        satoshis: outputSatoshis,
    }))
    //console.log('output script:', lockingScriptBuf.toString('hex'), outputSatoshis)
    recervierArray = Buffer.concat([recervierArray, address.hashBuffer])
    const tokenBuf = Buffer.alloc(8, 0)
    tokenBuf.writeBigUInt64LE(BigInt(outputTokenAmount))
    receiverTokenAmountArray = Buffer.concat([receiverTokenAmountArray, tokenBuf])
    const satoshiBuf = Buffer.alloc(8, 0)
    satoshiBuf.writeBigUInt64LE(BigInt(outputSatoshis))
    outputSatoshiArray = Buffer.concat([outputSatoshiArray, satoshiBuf])
  }

  if (changeSatoshis > 0) {
    const lockingScript = bsv.Script.buildPublicKeyHashOut(changeAddress)
    tx.addOutput(new bsv.Transaction.Output({
      script: lockingScript,
      satoshis: changeSatoshis,
    }))
    //console.log("addoutput:", lockingScript.toBuffer().toString('hex'), changeSatoshis)
  }

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const scriptInputIndex = tokenInputLen + satoshiInputArray.length
  for (let i = 0; i < tokenInputLen; i++) {
    const senderPrivKey = senderPrivKeyArray[i]
    const tokenInput = tokenInputArray[i]
    const tokenScript = tokenInput.lockingScript
    const satoshis = tokenInput.satoshis
    const inIndex = i
    const preimage = getPreimage(tx, tokenScript.toASM(), satoshis, inputIndex=inIndex, sighashType=sigtype)

    let sig = signTx(tx, senderPrivKey, tokenScript.toASM(), satoshis, inputIndex=inIndex, sighashType=sigtype)

    const tokenContract = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash.toString('hex')))
    const unlockingScript = tokenContract.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Bytes(prevouts.toString('hex')),
      new Bytes(tokenRabinMsg.toString('hex')),
      tokenRabinPaddingArray,
      tokenRabinSigArray,
      scriptInputIndex,
      new Bytes(scriptTx.serialize()),
      0,
      tokenOutputLen,
      new Bytes(prevPrevTokenAddress.hashBuffer.toString('hex')),
      prevPrevTokenAmount,
      new PubKey(toHex(senderPrivKey.publicKey)),
      new Sig(toHex(sig)),
      0,
      new Bytes('00'),
      0,
      1
    ).toScript()
    tx.inputs[inIndex].setScript(unlockingScript)
    //console.log('token transfer args:', toHex(preimage), toHex(senderPrivKey.publicKey), toHex(sig), tokenInputLen, prevouts.toString('hex'), rabinPubKey, rabinMsgArray.toString('hex'), rabinPaddingArray.toString('hex'), rabinSigArray.toString('hex'), tokenOutputLen, recervierArray.toString('hex'), receiverTokenAmountArray.toString('hex'), outputSatoshiArray.toString('hex'), changeSatoshis, changeAddress.hashBuffer.toString('hex'))
  }

  for (let i = 0; i < satoshiInputArray.length; i++) {
    const privKey = satoshiInputPrivKeyArray[i]
    const outputIndex = satoshiInputArray[i].outputIndex
    const hashData = bsv.crypto.Hash.sha256ripemd160(privKey.publicKey.toBuffer())
    const inputIndex = i + tokenInputLen
    const sig = tx.inputs[inputIndex].getSignatures(tx, privKey, inputIndex, sigtype, hashData)
    tx.inputs[inputIndex].addSignature(tx, sig[0])
  }

  // unlock routeCheckAmount
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  //console.log('rabinPubKeyArray:', rabinPubKeyArray)
  let preimage = getPreimage(tx, scriptTx.outputs[0].script.toASM(), scriptTx.outputs[0].satoshis, inputIndex=scriptInputIndex, sighashType=sigtype)
  const unlockingScript = routeCheckCode.unlock(
    new SigHashPreimage(toHex(preimage)),
    tokenInputLen,
    new Bytes(tokenInputArray[0].lockingScript.toBuffer().toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(checkRabinMsgArray.toString('hex')),
    new Bytes(checkRabinPaddingArray.toString('hex')),
    new Bytes(checkRabinSigArray.toString('hex')),
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    new Bytes(outputSatoshiArray.toString('hex')),
    changeSatoshis,
    new Ripemd160(changeAddress.hashBuffer.toString('hex'))
  ).toScript()
  tx.inputs[scriptInputIndex].setScript(unlockingScript)
  //console.log('token check contract args:', toHex(preimage), tokenInputLen, tokenInputArray[0].lockingScript.toBuffer().toString('hex'), prevouts.toString('hex'), checkRabinMsgArray.toString('hex'), checkRabinPaddingArray.toString('hex'), checkRabinSigArray.toString('hex'), inputTokenAddressArray.toString('hex'), inputTokenAmountArray.toString('hex'), outputSatoshiArray.toString('hex'), changeSatoshis, changeAddress.hashBuffer.toString('hex'))
  
  //console.log('createTokenTransferTx: ', tx.serialize())
  return tx
}