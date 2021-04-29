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

const Rabin = require('../rabin/rabin')
const Proto = require('./protoheader')
const TokenProto = require('./tokenProto')
const Common = require('./common')
const toBufferLE = Common.toBufferLE

const TokenUtil = module.exports

TokenUtil.RABIN_SIG_LEN = 128

const genesisFlag = Buffer.from('01', 'hex')
const nonGenesisFlag = Buffer.from('00', 'hex')
const tokenType = Buffer.alloc(4, 0)
tokenType.writeUInt32LE(1)
const PROTO_FLAG = Proto.PROTO_FLAG
// MSB of the sighash  due to lower S policy
const MSB_THRESHOLD = 0x7E

const Genesis = buildContractClass(loadDesc('tokenGenesis_desc.json'))
const Token = buildContractClass(loadDesc('token_desc.json'))
//const Genesis = buildContractClass(compileContract('tokenGenesis.scrypt'))
//const Token = buildContractClass(compileContract('tokenBtp.scrypt'))
const RouteCheck = buildContractClass(loadDesc('tokenRouteCheck_desc.json'))
const UnlockContractCheck = buildContractClass(loadDesc('tokenUnlockContractCheck_desc.json'))

const rabinPubKeyIndexArray = [0, 1]
const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID

let genesisContract
let routeCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash

TokenUtil.getUInt8Buf = Common.getUInt8Buf
TokenUtil.getUInt16Buf = Common.getUInt16Buf
TokenUtil.getUInt32Buf = Common.getUInt32Buf
TokenUtil.getUInt64Buf = Common.getUInt64Buf
TokenUtil.getTxIdBuf = Common.getTxIdBuf
TokenUtil.getScriptHashBuf = Common.getScriptHashBuf
TokenUtil.writeVarint = Common.writeVarint

TokenUtil.initContractHash = function(rabinPubKeyArray) {
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  let code = routeCheckCode.lockingScript.toBuffer()
  const routeCheckCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  routeCheckCodeHashArray = [routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash]

  const unlockContract = new UnlockContractCheck(rabinPubKeyArray)
  code = unlockContract.lockingScript.toBuffer()
  const unlockContractCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]
}

TokenUtil.createTokenContract = function(genesisHash, oracleData) {
  const tokenContract = new Token(Common.rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash))
  tokenContract.setDataPart(oracleData.toString('hex'))
  return tokenContract
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
  console.log('genesisHash:', genesisHash.toString('hex'))

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
      rabinPubKeyIndexArray,
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

  //console.log('creatToken:', tx.serialize())

  return [tokenContract, tx]
}

/** 
 * create routeCheckAmount contract utxo
 * @function createRouteCheckTx
 * @param bsvFeeTx {Object} bsv.Transction, the input bsv fee tx
 * @param bsvFeeOutputIndex {int} the input bsv utxo output index
 * @param inputPrivKey {Object} bsv.PrivateKey, the input bsv utxo unlocking key 
 * @param outputSatoshis {int} the routeCheckAmount contract utxo output satoshis
 * @param fee {int} the tx fee
 * @param changeAddress {Object} bsv.Address
 * @param nTokenInputs {Number} number of input tokens
 * @param tokenOutputArray {object[]} the token output array
 * @param rabinPubKeyArray {BigInt[]} rabin pubkey array
 * @param tokenID {Buffer} the tokenID
 * @param tokenCodeHash {Buffer} the token contract code hash
*/
TokenUtil.createRouteCheckTx = function(
  bsvFeeTx, 
  bsvFeeOutputIndex,
  inputPrivKey, 
  outputSatoshis,
  fee,
  changeAddress,
  nTokenInputs,
  tokenOutputArray,
  tokenIDBuf,
  tokenCodeHashBuf,
) {
  let receiverTokenAmountArray = Buffer.alloc(0)
  let recervierArray = Buffer.alloc(0)
  const nTokenOutputs = tokenOutputArray.length
  for (let i = 0; i < nTokenOutputs; i++) {
    const output = tokenOutputArray[i]
    recervierArray = Buffer.concat([recervierArray, output.address])
    receiverTokenAmountArray = Buffer.concat([
      receiverTokenAmountArray, 
      TokenUtil.getUInt64Buf(output.tokenAmount)
    ])
  }
  const routeCheck = new RouteCheck(Common.rabinPubKeyArray)
  const data = Buffer.concat([
    TokenUtil.getUInt32Buf(nTokenInputs),
    receiverTokenAmountArray,
    recervierArray,
    TokenUtil.getUInt32Buf(nTokenOutputs),
    tokenCodeHashBuf,
    tokenIDBuf,
  ])
  routeCheck.setDataPart(data.toString('hex'))

  const tx = Common.createScriptTx(bsvFeeTx, bsvFeeOutputIndex, routeCheck.lockingScript, outputSatoshis, fee, changeAddress, inputPrivKey)
  return [routeCheck, tx]
}

TokenUtil.createUnlockContractCheckTx = function(
  tokenIDBuf,
  tokenScriptCodeHashBuf,
  bsvFeeTx, 
  bsvFeeOutputIndex,
  inputPrivKey, 
  outputSatoshis,
  fee,
  changeAddress,
  tokenInputIndexArray,
  nTokenOutputs,
  tokenOutputAmountArray,
  tokenOutputAddressArray,
) {
  const unlockContractCheck = new UnlockContractCheck(Common.rabinPubKeyArray)

  const nTokenInputs = tokenInputIndexArray.length
  let tokenInputIndexBytes = Buffer.alloc(0)
  for (let i = 0; i < nTokenInputs; i++) {
    tokenInputIndexBytes = Buffer.concat([tokenInputIndexBytes, TokenUtil.getUInt32Buf(tokenInputIndexArray[i])]);
  }

  let receiverTokenAmountArray = Buffer.alloc(0)
  let recervierArray = Buffer.alloc(0)
  for (let i = 0; i < nTokenOutputs; i++) {
    recervierArray = Buffer.concat([recervierArray, tokenOutputAddressArray[i]])
    receiverTokenAmountArray = Buffer.concat([
      receiverTokenAmountArray, 
      TokenUtil.getUInt64Buf(tokenOutputAmountArray[i])
    ])
  }
  const data = Buffer.concat([
    tokenInputIndexBytes,
    TokenUtil.getUInt32Buf(nTokenInputs),
    receiverTokenAmountArray,
    recervierArray,
    TokenUtil.getUInt32Buf(nTokenOutputs),
    tokenScriptCodeHashBuf,
    tokenIDBuf,
  ])
  unlockContractCheck.setDataPart(data.toString('hex'))

  const tx = Common.createScriptTx(bsvFeeTx, bsvFeeOutputIndex, unlockContractCheck.lockingScript, outputSatoshis, fee, changeAddress, inputPrivKey)

  return [unlockContractCheck, tx]
}


TokenUtil.unlockToken = function(
  tx,
  tokenContract,
  inputIndex,
  tokenInputIndex,
  prevTokenTx,
  prevTokenOutputIndex,
  prevouts,
  checkScriptInputIndex,
  checkScriptTx,
  checkScriptTxOutputIndex,
  nReceivers,
  senderPubKeyHex,
  senderSigHex,
  lockContractInputIndex,
  lockConctractTxRaw,
  lockContractTxOutputIndex,
  op
) {

  const input = tx.inputs[inputIndex]
  const lockingScript = input.output.script
  const inputSatoshis = input.output.satoshis
  const preimage = getPreimage(tx, lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  let output = prevTokenTx.outputs[prevTokenOutputIndex]
  const prevTokenLockingScriptBuf = output.script.toBuffer()
  const prevTokenAddress = TokenProto.getTokenAddress(prevTokenLockingScriptBuf)
  const prevTokenAmount = TokenProto.getTokenAmount(prevTokenLockingScriptBuf)
  const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(prevTokenTx.id, prevTokenOutputIndex, output.satoshis, prevTokenLockingScriptBuf, tx.inputs[inputIndex].prevTxId)

  const unlockRes = tokenContract.unlock(
    new SigHashPreimage(toHex(preimage)),
    tokenInputIndex,
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    checkScriptInputIndex,
    new Bytes(checkScriptTx.toString('hex')),
    checkScriptTxOutputIndex,
    nReceivers,
    new Bytes(prevTokenAddress.toString('hex')),
    prevTokenAmount,
    new PubKey(senderPubKeyHex),
    new Sig(senderSigHex),
    lockContractInputIndex,
    new Bytes(lockConctractTxRaw),
    lockContractTxOutputIndex,
    op
  )
  const txContext = {
    tx: tx,
    inputIndex: inputIndex,
    inputSatoshis: inputSatoshis
  }
  const verifyRes = unlockRes.verify(txContext)
  console.log("unlockToken: verify res", verifyRes)
  //console.log('token unlock args:', toHex(preimage), toHex(senderPrivKey.publicKey), toHex(sig), tokenInputLen, prevouts.toString('hex'), rabinPubKey, rabinMsgArray.toString('hex'), rabinPaddingArray.toString('hex'), rabinSigArray.toString('hex'), nReceivers, recervierArray.toString('hex'), receiverTokenAmountArray.toString('hex'), outputSatoshiArray.toString('hex'), changeSatoshis, changeAddress.hashBuffer.toString('hex'))
  return unlockRes.toScript()
}

TokenUtil.unlockRouteCheck = function(
  tx,
  inputIndex,
  routeCheckContract,
  nTokenInputs,
  prevouts,
  nReceivers,
  changeSatoshis,
  changeAddress
) {

  const input = tx.inputs[inputIndex]
  const inputSatoshis = input.output.satoshis
  //console.log('rabinPubKeyArray:', rabinPubKeyArray)
  let preimage = getPreimage(tx, input.output.script.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  let inputTokenAmountArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)

  let checkRabinMsgArray = Buffer.alloc(0)
  let checkRabinPaddingArray = Buffer.alloc(0)
  let checkRabinSigArray = Buffer.alloc(0)
  // token input
  for (let i = 0; i < nTokenInputs; i++) {
    const input = tx.inputs[i]
    const tokenScriptBuf = input.output.script.toBuffer()
    const rabinMsg = Buffer.concat([
      TokenUtil.getTxIdBuf(input.prevTxId),
      TokenUtil.getUInt32Buf(input.outputIndex),
      TokenUtil.getUInt64Buf(input.output.satoshis),
      TokenUtil.getScriptHashBuf(tokenScriptBuf)
    ])
    checkRabinMsgArray = Buffer.concat([checkRabinMsgArray, rabinMsg])
    for (let j = 0; j < 2; j++) {
      const rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), Common.rabinPrivateKey.p, Common.rabinPrivateKey.q, Common.rabinPubKey)
      const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
      checkRabinSigArray = Buffer.concat([checkRabinSigArray, sigBuf])
      const paddingCountBuf = Buffer.alloc(2, 0)
      paddingCountBuf.writeUInt16LE(rabinSignResult.paddingByteCount)
      const padding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
      checkRabinPaddingArray = Buffer.concat([
        checkRabinPaddingArray,
        paddingCountBuf,
        padding
      ])
    }

    inputTokenAddressArray = Buffer.concat([
      inputTokenAddressArray,
      TokenProto.getTokenAddress(tokenScriptBuf)
    ])
    inputTokenAmountArray = Buffer.concat([
      inputTokenAmountArray,
      TokenUtil.getUInt64Buf(TokenProto.getTokenAmount(tokenScriptBuf)),
    ])
  }

  let outputSatoshiArray = Buffer.alloc(0)
  for (let i = 0; i < nReceivers; i++) {
    outputSatoshiArray = Buffer.concat([outputSatoshiArray, TokenUtil.getUInt64Buf(tx.outputs[i].satoshis)])
  }

  const tokenScriptHex = tx.inputs[0].output.script.toBuffer().toString('hex')
  const unlockRes = routeCheckContract.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(tokenScriptHex),
    new Bytes(prevouts.toString('hex')),
    new Bytes(checkRabinMsgArray.toString('hex')),
    new Bytes(checkRabinPaddingArray.toString('hex')),
    new Bytes(checkRabinSigArray.toString('hex')),
    rabinPubKeyIndexArray,
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    new Bytes(outputSatoshiArray.toString('hex')),
    changeSatoshis,
    new Ripemd160(changeAddress.hashBuffer.toString('hex'))
  )
  const txContext =  {
    tx: tx,
    inputIndex: inputIndex,
    inputSatoshis: inputSatoshis
  }
  console.log('unlockRouteCheck verify res:', unlockRes.verify(txContext))
  //console.log('token check contract args:', toHex(preimage), tokenInputLen, tokenScriptHex, prevouts.toString('hex'), checkRabinMsgArray.toString('hex'), checkRabinPaddingArray.toString('hex'), checkRabinSigArray.toString('hex'), inputTokenAddressArray.toString('hex'), inputTokenAmountArray.toString('hex'), outputSatoshiArray.toString('hex'), changeSatoshis, changeAddress.hashBuffer.toString('hex'))
  return unlockRes.toScript()
}

TokenUtil.unlockUnlockContractCheck = function(
  tx,
  inputIndex,
  unlockContractCheck,
  inputTokenIndexes,
  outputTokenIndexes,
  prevouts,
  isBurn
) {
  const input = tx.inputs[inputIndex]
  const inputSatoshis = input.output.satoshis
  const preimage = getPreimage(tx, unlockContractCheck.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  let inputRabinMsgArray = Buffer.alloc(0)
  let inputRabinPaddingArray = Buffer.alloc(0)
  let inputRabinSignArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)
  let inputTokenAmountArray = Buffer.alloc(0)
  let inputTokenIndexArray = Buffer.alloc(0)
  let tokenScript
  for (let i = 0; i < inputTokenIndexes.length; i++) {
    const tokenInput = tx.inputs[inputTokenIndexes[i]]
    tokenScript = tokenInput.output.script
    const msg = Buffer.concat([
      TokenUtil.getTxIdBuf(tokenInput.prevTxId),
      TokenUtil.getUInt32Buf(tokenInput.outputIndex),
      TokenUtil.getUInt64Buf(tokenInput.output.satoshis),
      Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenScript.toBuffer()))
    ])
    inputTokenIndexArray = Buffer.concat([
      inputTokenIndexArray,
      TokenUtil.getUInt32Buf(inputTokenIndexes[i])
    ])
    inputRabinMsgArray = Buffer.concat([
      inputRabinMsgArray,
      msg
    ])
    inputTokenAddressArray = Buffer.concat([
      inputTokenAddressArray,
      TokenProto.getTokenAddress(tokenScript.toBuffer())
    ])
    inputTokenAmountArray = Buffer.concat([
      inputTokenAmountArray,
      TokenUtil.getUInt64Buf(TokenProto.getTokenAmount(tokenScript.toBuffer()))
    ])

    const rabinSignResult = Rabin.sign(msg.toString('hex'), Common.rabinPrivateKey.p, Common.rabinPrivateKey.q, Common.rabinPubKey)
    let padding = Buffer.concat([
      TokenUtil.getUInt16Buf(rabinSignResult.paddingByteCount),
      Buffer.alloc(rabinSignResult.paddingByteCount)
    ])
    inputRabinPaddingArray = Buffer.concat([
      inputRabinPaddingArray,
      padding, 
      padding
    ])
    const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
    inputRabinSignArray = Buffer.concat([
      inputRabinSignArray,
      sigBuf, 
      sigBuf
    ])
  }

  let otherOutputArray = Buffer.alloc(0)
  let tokenOutputSatoshiArray = Buffer.alloc(0)
  let tokenOutputIndexArray = Buffer.alloc(0)
  let j = 0;
  const nOutputs = tx.outputs.length
  for (let i = 0; i < nOutputs; i++) {
    const tokenOutIndex = outputTokenIndexes[j]
    if (i == tokenOutIndex) {
      tokenOutputIndexArray = Buffer.concat([
        tokenOutputIndexArray,
        TokenUtil.getUInt32Buf(tokenOutIndex)
      ])
      tokenOutputSatoshiArray = Buffer.concat([
        tokenOutputSatoshiArray,
        TokenUtil.getUInt64Buf(tx.outputs[i].satoshis)
      ])
      j++
    } else {
      const output = tx.outputs[i]
      const outputBuf = Common.buildOutput(output.script.toBuffer(), output.satoshis)
      otherOutputArray = Buffer.concat([
        otherOutputArray,
        TokenUtil.getUInt32Buf(outputBuf.length),
        outputBuf
      ])
    }
  }

  const unlockRes = unlockContractCheck.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(tokenScript.toBuffer().toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(inputRabinMsgArray.toString('hex')),
    new Bytes(inputRabinPaddingArray.toString('hex')),
    new Bytes(inputRabinSignArray.toString('hex')),
    [0, 1],
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    nOutputs,
    new Bytes(tokenOutputIndexArray.toString('hex')),
    new Bytes(tokenOutputSatoshiArray.toString('hex')),
    new Bytes(otherOutputArray.toString('hex'))
  )
  const txContext = {
    tx: tx,
    inputIndex: inputIndex,
    inputSatoshis: inputSatoshis
  }
  console.log('unlockUnlockContractCheck verify res', unlockRes.verify(txContext))
  return unlockRes.toScript()
}

/** 
 * create tx from token transfer
 * @function createTokenTransfer
 * @param routeCheckTx {Object} bsv.Transaction, routeCheckAmount contract tx
 * @param tokenInputArray {Array of token input data} token input params, input data: {lockingScript: {bsv.Script}, satoshis: {number}, txId: {hex string}, outputIndex: {number}}
 * @param satoshiInputArray {object[]} bsv input params, the input data format is same as token input data
 * @param rabinPubKeyArray {BigInt[]} rabin public key array
 * @param senderPrivKeyArray {object[]} Array of bsv.PrivateKey, the input token unlocking private keys
 * @param satoshiInputPrivKeyArray {object[]} Array of bsv.PrivateKey, the common bsv input unlocking private keys
 * @param tokenOutputArray {object[]} token output params, token output data: {address: {bsv.Address}, tokenAmount: {number}, satoshis: {number}}
 * @param changeSatoshis {number} change output satoshis
 * @param changeAddress {object} bsv.Address, change output address
*/
TokenUtil.createTokenTransfer = function(
  routeCheckTx,
  routeCheck,
  tokenInputArray,
  satoshiInputArray,
  rabinPubKeyArray,
  senderPrivKeyArray,
  satoshiInputPrivKeyArray, 
  tokenOutputArray,
  fee,
  changeAddress 
) {
  const tx = new bsv.Transaction()

  const tokenInputLen = tokenInputArray.length
  let inputTokenScript
  let prevouts = []

  // token input
  for (let i = 0; i < tokenInputLen; i++) {
    const tokenInput = tokenInputArray[i]
    const tokenScript = tokenInput.lockingScript
    inputTokenScript = tokenScript
    Common.addInput(tx, tokenInput.txId, tokenInput.outputIndex, tokenScript, tokenInput.satoshis, prevouts)
  }

  // bsv input
  for (let i = 0; i < satoshiInputArray.length; i++) {
    const feetx = satoshiInputArray[i].tx
    const outputIndex = satoshiInputArray[i].outputIndex
    const output = feetx.outputs[outputIndex]
    Common.addInput(tx, feetx.id, outputIndex, output.script, output.satoshis, prevouts, p2pkh=true)
  }

  // checkScript
  const checkScriptInputIndex = tokenInputLen + satoshiInputArray.length
  Common.addInput(tx, routeCheckTx.id, 0, routeCheckTx.outputs[0].script, routeCheckTx.outputs[0].satoshis, prevouts)

  prevouts = Buffer.concat(prevouts)

  // sum input satoshis
  let sumInputSatoshis = 0
  for (let i = 0; i < tx.inputs.length; i++) {
    sumInputSatoshis += tx.inputs[i].output.satoshis
  }

  let changeSatoshis = sumInputSatoshis - fee
  const nReceivers = tokenOutputArray.length
  for (let i = 0; i < nReceivers; i++) {
    const tokenOutput = tokenOutputArray[i]
    const address = tokenOutput.address
    const outputTokenAmount = tokenOutput.tokenAmount
    const outputSatoshis = tokenOutput.satoshis
    const lockingScriptBuf = TokenProto.getNewTokenScript(inputTokenScript.toBuffer(), address, outputTokenAmount) 
    tx.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.fromBuffer(lockingScriptBuf),
        satoshis: outputSatoshis,
    }))
    changeSatoshis -= outputSatoshis
    //console.log('output script:', lockingScriptBuf.toString('hex'), outputSatoshis)
  }

  if (changeSatoshis > 0) {
    const lockingScript = bsv.Script.buildPublicKeyHashOut(changeAddress)
    tx.addOutput(new bsv.Transaction.Output({
      script: lockingScript,
      satoshis: changeSatoshis,
    }))
    //console.log("addoutput:", lockingScript.toBuffer().toString('hex'), changeSatoshis)
  }

  const scriptInputIndex = tokenInputLen + satoshiInputArray.length
  for (let i = 0; i < tokenInputLen; i++) {
    const senderPrivKey = senderPrivKeyArray[i]
    const tokenInput = tokenInputArray[i]
    const tokenScript = tokenInput.lockingScript
    const satoshis = tokenInput.satoshis
    const inIndex = i

    let sig = signTx(tx, senderPrivKey, tokenScript.toASM(), satoshis, inputIndex=inIndex, sighashType=sigtype)

    const tokenContract = tokenInput.tokenContract
    const unlockingScript = TokenUtil.unlockToken(tx, tokenContract, inIndex, inIndex, tokenInput.prevTokenTx, tokenInput.prevTokenOutputIndex, prevouts, checkScriptInputIndex, routeCheckTx, 0, nReceivers, toHex(senderPrivKey.publicKey), toHex(sig), 0, '00', 0, TokenProto.OP_TRANSFER)
    tx.inputs[inIndex].setScript(unlockingScript)
  }

  for (let i = 0; i < satoshiInputArray.length; i++) {
    const privKey = satoshiInputPrivKeyArray[i]
    const inputIndex = i + tokenInputLen
    Common.signP2PKH(tx, privKey, inputIndex)
  }

  let unlockingScript = TokenUtil.unlockRouteCheck(tx, scriptInputIndex, routeCheck, tokenInputArray.length, prevouts, nReceivers, changeSatoshis, changeAddress)
  tx.inputs[scriptInputIndex].setScript(unlockingScript)
  
  //console.log('createTokenTransferTx: ', tx.serialize())
  return tx
}