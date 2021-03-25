const { expect } = require('chai');
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
  inputSatoshis,
  DataLen,
  dummyTxId,
  compileContract,
  sighashType2Hex
} = require('../../helper');
const {toBufferLE} = require('bigint-buffer')

const {
    privateKey,
    privateKey2,
} = require('../../privateKey');
const Proto = require('../../deployments/protoheader')

const{ generatePrivKey,
  privKeyToPubKey,
  sign,
  verify } = require("../../rabin/rabin");

//const rabinPrivateKey = generatePrivKey()
const rabinPrivateKey = {
  "p": 5757440790098238249206056886132360783939976756626308615141839695681752813612764520921497694519841722889028334119917789649651692480869415368298368200263n,
  "q": 650047001204168007801848889418948532353073326909497585177081016045346562912146630794965372241635285465610094863279373295872825824127728241709483771067n
}
const rabinPubKey = privKeyToPubKey(rabinPrivateKey.p, rabinPrivateKey.q)
const rabinPubKeyArray = [rabinPubKey, rabinPubKey, rabinPubKey]
//console.log('rabin key pair:', rabinPrivateKey, rabinPubKey)

const TokenProto = require('../../deployments/tokenProto')
const TokenUtil = require('../../deployments/tokenUtil')

const OP_TRANSFER = 1
const OP_UNLOCK_FROM_CONTRACT = 2

// make a copy since it will be mutated
let tx
let prevScriptTx
const prevScriptOutIndex = 0
const outputToken1 = 100

const tokenName = Buffer.alloc(20, 0)
tokenName.write('test token name')
const tokenSymbol = Buffer.alloc(10, 0)
tokenSymbol.write('ttn')
const issuerPubKey = privateKey.publicKey
const genesisFlag = Buffer.from('01', 'hex')
const nonGenesisFlag = Buffer.from('00', 'hex')
const tokenType = Buffer.alloc(4, 0)
tokenType.writeUInt32LE(1)
const PROTO_FLAG = Proto.PROTO_FLAG

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()
const tokenValue = 1000
const tokenValue1 = 50
const tokenValue2 = tokenValue - tokenValue1
const buffValue = Buffer.alloc(8, 0)
buffValue.writeBigUInt64LE(BigInt(tokenValue))
const tokenID = Buffer.concat([
  Buffer.from(dummyTxId, 'hex').reverse(),
  Buffer.alloc(4, 0),
])
let routeCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash
let tokenCodeHash
let tokenInstance = []
let routeCheckInstance
let unlockContractCheckInstance

const maxInputLimit = 3
const maxOutputLimit = 3

const decimalNum = Buffer.from('08', 'hex')

let Token, RouteCheck, UnlockContractCheck, TokenSell

function genContract(name, use_desc) {
  if (use_desc) {
    return buildContractClass(loadDesc(name + '_desc.json'))
  }
  else {
    return buildContractClass(compileContract(name + '.scrypt'))
  }
}

function initContract() {
  const use_desc = true
  Token = genContract('token', use_desc)
  RouteCheck = genContract('tokenRouteCheck', use_desc)
  UnlockContractCheck = genContract('tokenUnlockContractCheck', use_desc)
  TokenSell = genContract('tokenSell', true)
}

function initContractHash() {
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  let code = routeCheckCode.lockingScript.toBuffer()
  const routeCheckCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  routeCheckCodeHashArray = [routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash]

  const unlockContract = new UnlockContractCheck(rabinPubKeyArray)
  code = unlockContract.lockingScript.toBuffer()
  const unlockContractCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]

  //TODO:
  genesisHash = routeCheckCodeHash

  const tokenContract = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, genesisHash)
  code = tokenContract.lockingScript.toBuffer()
  tokenCodeHash = bsv.crypto.Hash.sha256ripemd160(code)
}

function createTokenContract(addressBuf, amount) {
  const token = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, genesisHash)
  const data = Buffer.concat([
    tokenName,
    tokenSymbol,
    nonGenesisFlag, 
    decimalNum,
    addressBuf,
    TokenUtil.getUInt64Buf(amount),
    Buffer.from(tokenID, 'hex'),
    tokenType, // type
    PROTO_FLAG
  ])
  token.setDataPart(data.toString('hex'))
  return token
}

function genReceiverData(nOutputs, outputTokenArray) {
  let recervierArray = Buffer.alloc(0)
  let receiverTokenAmountArray = Buffer.alloc(0)
  let receiverSatoshiArray = Buffer.alloc(0)
  for (let i = 0; i < nOutputs; i++) {
    recervierArray = Buffer.concat([recervierArray, address2.hashBuffer])
    const tokenBuf = Buffer.alloc(8, 0)
    tokenBuf.writeBigUInt64LE(BigInt(outputTokenArray[i]))
    receiverTokenAmountArray = Buffer.concat([receiverTokenAmountArray, tokenBuf])
    const satoshiBuf = Buffer.alloc(8, 0)
    satoshiBuf.writeBigUInt64LE(BigInt(inputSatoshis))
    receiverSatoshiArray = Buffer.concat([receiverSatoshiArray, satoshiBuf])
  }
  return {recervierArray, receiverTokenAmountArray, receiverSatoshiArray}
}

function genUnlockContractCheckTx(nOutputs, outputTokenArray) {
  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nOutputs, outputTokenArray)
  prevScriptTx = new bsv.Transaction()
  prevScriptTx.addInput(new bsv.Transaction.Input({
    prevTxId: dummyTxId,
    outputIndex: 0,
    script: ''
  }), bsv.Script.buildPublicKeyHashOut(address1), inputSatoshis)
  const nReceiverBuf = Buffer.alloc(1, 0)
  nReceiverBuf.writeUInt8(nOutputs)
  const unlockContractCheck = new UnlockContractCheck(rabinPubKeyArray)
  const data = Buffer.concat([
    receiverTokenAmountArray,
    recervierArray,
    nReceiverBuf,
    tokenCodeHash,
    tokenID,
  ])
  unlockContractCheck.setDataPart(data.toString('hex'))
  const unlockCheckScript = unlockContractCheck.lockingScript
  prevScriptTx.addOutput(new bsv.Transaction.Output({
    script: unlockCheckScript,
    satoshis: inputSatoshis
  }))
  unlockContractCheckInstance = unlockContractCheck
  return prevScriptTx
}

function addInput(tx, lockingScript, i, prevouts, prevTxId=null) {
  if (prevTxId === null) {
    prevTxId = dummyTxId
  }
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: prevTxId,
    outputIndex: i,
    script: ''
  }), lockingScript, inputSatoshis)
  prevouts.push(TokenUtil.getTxIdBuf(prevTxId))
  prevouts.push(TokenUtil.getUInt32Buf(i))
}

function addOutput(tx, lockingScript, outputSatoshis=inputSatoshis) {
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputSatoshis
  }))
}

function createRabinMsg(txid, outputIndex, satoshis, scriptBuf, spendByTxId=null) {
  const scriptHash = bsv.crypto.Hash.sha256ripemd160(scriptBuf)
  let rabinMsg = Buffer.concat([
    TokenUtil.getTxIdBuf(txid),
    TokenUtil.getUInt32Buf(outputIndex),
    TokenUtil.getUInt64Buf(satoshis),
    scriptHash
  ])
  if (spendByTxId !== null) {
    rabinMsg = Buffer.concat([rabinMsg, TokenUtil.getTxIdBuf(spendByTxId)])
  }
  let rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
  const rabinSign = rabinSignResult.signature
  const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
  let rabinPaddingArray = []
  let rabinSigArray = []
  for (let i = 0; i < 2; i++) {
    rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
    rabinSigArray.push(rabinSign)
  }
  return [rabinMsg, rabinPaddingArray, rabinSigArray]
}

function createRouteCheckContract(nOutputs, outputTokenArray) {
  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nOutputs, outputTokenArray)
  const tx = new bsv.Transaction()
  addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])

  const nReceiverBuf = TokenUtil.getUInt8Buf(nOutputs)
  const routeCheck = new RouteCheck(rabinPubKeyArray)
  const data = Buffer.concat([
    receiverTokenAmountArray,
    recervierArray,
    nReceiverBuf,
    tokenCodeHash,
    tokenID,
  ])
  routeCheck.setDataPart(data.toString('hex'))
  const routeCheckScript = routeCheck.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: routeCheckScript,
    satoshis: inputSatoshis
  }))
  routeCheckInstance = routeCheck
  return [routeCheck, tx]
}

function verifyRouteCheck(tx, prevouts, tokenInstance, nTokenInput, nSatoshiInput, receiverSatoshiArray, changeSatoshi, inputIndex, expected) {

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }

  let rabinMsgArray = Buffer.alloc(0)
  let rabinSignArray = Buffer.alloc(0)
  let rabinPaddingArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)
  let inputTokenAmountArray = Buffer.alloc(0)
  let tokenScript
  for (let i = 0; i < nTokenInput; i++) {
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(i)
    const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())

    const token = tokenInstance[i]
    tokenScript = token.lockingScript.toBuffer()

    const address = TokenProto.getTokenAddress(tokenScript)
    inputTokenAddressArray = Buffer.concat([inputTokenAddressArray, address])
    const amount = TokenProto.getTokenAmount(tokenScript)
    const amountBuf = Buffer.alloc(8, 0)
    amountBuf.writeBigUInt64LE(BigInt(amount))
    inputTokenAmountArray = Buffer.concat([inputTokenAmountArray, amountBuf])

    const scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenScript))
    const bufValue = Buffer.alloc(8, 0)
    bufValue.writeBigUInt64LE(BigInt(outputToken1 + i))
    const satoshiBuf = Buffer.alloc(8, 0)
    satoshiBuf.writeBigUInt64LE(BigInt(inputSatoshis))
    const rabinMsg = Buffer.concat([
      txidBuf,
      indexBuf,
      satoshiBuf,
      scriptHash,
    ])
    rabinMsgArray = Buffer.concat([
      rabinMsgArray,
      rabinMsg,
    ])
    //console.log('rabinsignature:', msg.toString('hex'), rabinSignResult.paddingByteCount, rabinSignResult.signature)

    for (let j = 0; j < 2; j++) {
      const rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
      const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
      rabinSignArray = Buffer.concat([rabinSignArray, sigBuf])
      const paddingCountBuf = Buffer.alloc(2, 0)
      paddingCountBuf.writeUInt16LE(rabinSignResult.paddingByteCount)
      const padding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
      rabinPaddingArray = Buffer.concat([
        rabinPaddingArray,
        paddingCountBuf,
        padding
      ])
    }
  }

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, routeCheckInstance.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const result = routeCheckInstance.unlock(
    new SigHashPreimage(toHex(preimage)),
    nTokenInput,
    new Bytes(tokenScript.toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsgArray.toString('hex')),
    new Bytes(rabinPaddingArray.toString('hex')),
    new Bytes(rabinSignArray.toString('hex')),
    [0, 1],
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    new Bytes(receiverSatoshiArray.toString('hex')),
    changeSatoshi,
    new Ripemd160(address1.hashBuffer.toString('hex'))
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
}

function verifyTokenContract(nTokenInput, nTokenOutputs, expectedToken, expectedCheck, nSatoshiInput=0, changeSatoshi=0, outputTokenAdd=0) {
  const tx =  new bsv.Transaction()
  let prevouts = []

  let sumInputTokens = 0
  let tokenInstance = []
  let tokenScriptBuf
  // add token input
  for (let i = 0; i < nTokenInput; i++) {
    const token = createTokenContract(address1.hashBuffer, outputToken1 + i)
    tokenInstance.push(token)
    tokenScriptBuf = token.lockingScript.toBuffer()
    sumInputTokens += outputToken1 + i
    addInput(tx, token.lockingScript, i, prevouts)
  }

  // add bsv input
  for (let i = 0; i < nSatoshiInput; i++) {
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), i + nTokenInput, prevouts)
  }

  sumInputTokens += outputTokenAdd
  let outputTokenArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    if (i == nTokenOutputs - 1) {
      outputTokenArray.push(sumInputTokens)
    } else {
      sumInputTokens -= i + 1
      outputTokenArray.push(i + 1)
    }
  }

  // add tokenRouteCheckContract
  const [routeCheck, routeCheckTx] = createRouteCheckContract(nTokenOutputs, outputTokenArray)
  const contractInputIndex = nTokenInput + nSatoshiInput
  addInput(tx, routeCheck.lockingScript, contractInputIndex, prevouts, prevTxId=routeCheckTx.id)

  prevouts = Buffer.concat(prevouts)

  // output
  for (let i = 0; i < nTokenOutputs; i++) {
    const scriptBuf = TokenProto.getNewTokenScript(tokenScriptBuf, address2.hashBuffer, outputTokenArray[i])
    addOutput(tx, bsv.Script.fromBuffer(scriptBuf))
  }

  if (changeSatoshi > 0) {
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), changeSatoshi)
  }

  //console.log('outputTokenArray:', outputTokenArray)
  for (let i = 0; i < nTokenInput; i++) {
    verifyOneTokenContract(tx, prevouts, tokenInstance[i], nTokenOutputs, i, contractInputIndex, routeCheckTx, 0, expectedToken)
  }

  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nTokenOutputs, outputTokenArray)
  verifyRouteCheck(tx, prevouts, tokenInstance, nTokenInput, nSatoshiInput, receiverSatoshiArray, changeSatoshi, contractInputIndex, expectedCheck)
}

function verifyOneTokenContract(tx, prevouts, token, nOutputs, inputIndex, contractInputIndex, contractTx, contractTxOutputIndex, expected) {
  //console.log('verifyOneTokenContract:', inputIndex, expected)
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }

  const scriptBuf = token.lockingScript.toBuffer()
  let prevTokenAddress = TokenProto.getTokenAddress(scriptBuf)
  let prevTokenAmount = TokenProto.getTokenAmount(scriptBuf)
  const [rabinMsg, rabinPaddingArray, rabinSigArray] = createRabinMsg(dummyTxId, inputIndex, inputSatoshis, scriptBuf, dummyTxId)

  const result = token.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    [0, 1],
    contractInputIndex,
    new Bytes(contractTx.toString('hex')),
    contractTxOutputIndex,
    nOutputs,
    new Bytes(prevTokenAddress.toString('hex')),
    prevTokenAmount,
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    0,
    new Bytes('00'),
    0,
    OP_TRANSFER
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
  //return result
}

function unlockFromContract(scriptHash=null) {
  const prevTx = new bsv.Transaction()
  prevTx.addInput(new bsv.Transaction.Input({
    prevTxId: dummyTxId,
    outputIndex: 0,
    script: ''
  }), bsv.Script.buildPublicKeyHashOut(address1), inputSatoshis)
  const sellSatoshis = 10000
  const tokenSell = new TokenSell(new Ripemd160(address1.hashBuffer.toString('hex')), sellSatoshis)
  const sellScript = tokenSell.lockingScript
  prevTx.addOutput(new bsv.Transaction.Output({
    script: sellScript,
    satoshis: inputSatoshis
  }))
  if (scriptHash === null) {
    scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(sellScript.toBuffer()))
  }

  const bufValue = Buffer.alloc(8, 0)
  const inputTokenAmount = sellSatoshis * 10;
  bufValue.writeBigUInt64LE(BigInt(inputTokenAmount))
  const oracleData = Buffer.concat([
    tokenName,
    tokenSymbol,
    nonGenesisFlag,
    decimalNum,
    scriptHash, // contract script hash
    bufValue, // token value
    tokenID, // script code hash
    tokenType, // type
    PROTO_FLAG
    ])

  const token = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, genesisHash)
  //token.replaceAsmVars(asmVars)
  token.setDataPart(oracleData.toString('hex'))
  const tokenScript = token.lockingScript

  tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: dummyTxId,
    outputIndex: 0,
    script: ''
    }), tokenScript, inputSatoshis)
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: prevTx.id,
    outputIndex: 0,
    script: ''
    }), sellScript, inputSatoshis)

  const nTokenOutputs = 1
  const outputTokenArray = [inputTokenAmount]
  const checkScriptTx = genUnlockContractCheckTx(nTokenOutputs, outputTokenArray)
  const checkScriptTxId = checkScriptTx.id

  tx.addInput(new bsv.Transaction.Input({
    prevTxId: checkScriptTxId,
    outputIndex: 0,
    script: ''
    }), checkScriptTx.outputs[0].script, inputSatoshis)

  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(address1),
    satoshis: sellSatoshis
  }))

  const tokenScriptBuffer = TokenProto.getNewTokenScript(tokenScript.toBuffer(), address2.hashBuffer, inputTokenAmount)
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.fromBuffer(tokenScriptBuffer),
    satoshis: inputSatoshis
  }))

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=0, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: 0, 
    inputSatoshis: inputSatoshis 
  }
  const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())
  const indexBuf = Buffer.alloc(4, 0)
  indexBuf.writeUInt32LE(0)
  const txidBuf2 = Buffer.from([...Buffer.from(prevTx.id, 'hex')].reverse())
  const txidBuf3 = Buffer.from([...Buffer.from(checkScriptTx.id, 'hex')].reverse())
  const prevouts = Buffer.concat([
    txidBuf,
    indexBuf,
    txidBuf2,
    indexBuf,
    txidBuf3,
    indexBuf
  ])
  const txContext2 = { 
    tx: tx, 
    inputIndex: 2, 
    inputSatoshis: inputSatoshis
  }
  const satoshiBuf = Buffer.alloc(8, 0)
  satoshiBuf.writeBigUInt64LE(BigInt(inputSatoshis))
  const scriptBuf = token.lockingScript.toBuffer()
  const tokenScriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(scriptBuf))
  const rabinMsg = Buffer.concat([
    txidBuf,
    indexBuf,
    satoshiBuf,
    tokenScriptHash,
    txidBuf,
  ])
  let rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
  const rabinSign = rabinSignResult.signature
  const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
  let rabinPaddingArray = []
  let rabinSigArray = []
  for (let i = 0; i < 2; i++) {
    rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
    rabinSigArray.push(rabinSign)
  }

  const contractInputIndex = 2
  const checkPreimage = getPreimage(tx, unlockContractCheckInstance.lockingScript.toASM(), inputSatoshis, inputIndex=contractInputIndex, sighashType=sigtype)

  let inputRabinMsgArray = Buffer.concat([
    TokenUtil.getTxIdBuf(dummyTxId),
    TokenUtil.getUInt32Buf(0),
    TokenUtil.getUInt64Buf(inputSatoshis),
    Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenScript.toBuffer()))
  ])
  rabinSignResult = sign(inputRabinMsgArray.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
  let padding = Buffer.concat([
    TokenUtil.getUInt16Buf(rabinSignResult.paddingByteCount),
    Buffer.alloc(rabinSignResult.paddingByteCount)
  ])
  const inputRabinPaddingArray = Buffer.concat([
    padding, padding
  ])
  const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
  let inputRabinSignArray = Buffer.concat([
    sigBuf, sigBuf
  ])

  let inputTokenIndexArray = TokenUtil.getUInt32Buf(0)
  let inputTokenAddressArray = TokenProto.getTokenAddress(tokenScript.toBuffer())
  let inputTokenAmountArray = TokenUtil.getUInt64Buf(TokenProto.getTokenAmount(tokenScript.toBuffer()))
  let tokenOutputIndexArray = TokenUtil.getUInt32Buf(1) 
  let tokenOutputSatoshiArray = TokenUtil.getUInt64Buf(inputSatoshis)
  const outScriptBuf = TokenUtil.buildOutput(bsv.Script.buildPublicKeyHashOut(address1).toBuffer(), sellSatoshis)
  const outScriptLength = Buffer.alloc(4, 0) 
  outScriptLength.writeUInt32LE(outScriptBuf.length)
  const otherOutputArray = Buffer.concat([outScriptLength, outScriptBuf])

  const nTokenInput = 1
  const nOutputs = 2
  const result = unlockContractCheckInstance.unlock(
    new SigHashPreimage(toHex(checkPreimage)),
    nTokenInput,
    new Bytes(tokenScript.toBuffer().toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(inputRabinMsgArray.toString('hex')),
    new Bytes(inputRabinPaddingArray.toString('hex')),
    new Bytes(inputRabinSignArray.toString('hex')),
    [0, 1],
    new Bytes(inputTokenIndexArray.toString('hex')),
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    nOutputs,
    new Bytes(tokenOutputIndexArray.toString('hex')),
    new Bytes(tokenOutputSatoshiArray.toString('hex')),
    new Bytes(otherOutputArray.toString('hex')),
    false
  ).verify(txContext2)
  expect(result.success, result.error).to.be.true

  return {token, preimage, prevouts, prevTx, txContext, checkScriptTx, txContext2, rabinMsg, rabinPaddingArray, rabinSigArray}
}

describe('Test token contract unlock In Javascript', () => {
  before(() => {
    initContract()
    initContractHash()
  });

  it('should succeed with multi input and output', () => {
    for (let i = 1; i <= 3; i++) {
      for (let j = 1; j <= 3; j++) {
        verifyTokenContract(i, j, true, true, 0, 0)
      }
    }
    verifyTokenContract(maxInputLimit, maxOutputLimit, true, true, 0, 0)
  });

  it('should succeed with bsv input', () => {
    for (let i = 1; i <= 3; i++) {
      for (let j = 1; j <= 3; j++) {
        //console.log("verify token contract:", i, j)
        verifyTokenContract(i, j, true, true, 2, 1000)
      }
    }
    verifyTokenContract(maxInputLimit, maxOutputLimit, true, true, 2, 1000)
  });

  it('it should succeed when using unlockFromContract', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext, checkScriptTx, txContext2, rabinMsg, rabinPaddingArray, rabinSigArray} = unlockFromContract()
    const prevTokenAddress = new Bytes(address1.hashBuffer.toString('hex'))
    const prevTokenAmount = 0
    const result = token.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Bytes(prevouts.toString('hex')),
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      [0, 1],
      2,
      new Bytes(checkScriptTx.serialize()),
      0,
      1,
      prevTokenAddress,
      prevTokenAmount,
      new PubKey('00'),
      new Sig('00'),
      1,
      new Bytes(prevTx.serialize()),
      0,
      OP_UNLOCK_FROM_CONTRACT
    ).verify(txContext)
    expect(result.success, result.error).to.be.true
  });

  it('it should failed when unlockFromContract with wrong prevTx', () => {
    const {token, preimage, prevouts, prevTx, txContext, checkScriptTx, txContext2, rabinMsg, rabinPaddingArray, rabinSigArray} = unlockFromContract()
    const prevTokenAddress = new Bytes(address1.hashBuffer.toString('hex'))
    const prevTokenAmount = 0
    prevTx.nLockTime = 1
    const result = token.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Bytes(prevouts.toString('hex')),
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      [0, 1],
      2,
      new Bytes(checkScriptTx.serialize()),
      0,
      1,
      prevTokenAddress,
      prevTokenAmount,
      new PubKey('00'),
      new Sig('00'),
      1,
      new Bytes(prevTx.serialize()),
      0,
      OP_UNLOCK_FROM_CONTRACT
    ).verify(txContext)
    expect(result.success, result.error).to.be.false
  });

  it('it should failed when unlockFromContract with wrong contract script hash', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext, checkScriptTx, txContext2, rabinMsg, rabinPaddingArray, rabinSigArray} = unlockFromContract(address2.hashBuffer)
    const prevTokenAddress = new Bytes(address1.hashBuffer.toString('hex'))
    const prevTokenAmount = 0
    const result = token.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Bytes(prevouts.toString('hex')),
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      [0, 1],
      2,
      new Bytes(checkScriptTx.serialize()),
      0,
      1,
      prevTokenAddress,
      prevTokenAmount,
      new PubKey('00'),
      new Sig('00'),
      1,
      new Bytes(prevTx.serialize()),
      0,
      OP_UNLOCK_FROM_CONTRACT
    ).verify(txContext)
    expect(result.success, result.error).to.be.false
  });

  it('it should failed when pass same rabinPubKey index', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext, checkScriptTx, txContext2, rabinMsg, rabinPaddingArray, rabinSigArray} = unlockFromContract()
    const prevTokenAddress = new Bytes(address1.hashBuffer.toString('hex'))
    const prevTokenAmount = 0
    const result = token.unlock(
      new SigHashPreimage(toHex(preimage)),
      new Bytes(prevouts.toString('hex')),
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      [1, 1],
      2,
      new Bytes(checkScriptTx.serialize()),
      0,
      1,
      prevTokenAddress,
      prevTokenAmount,
      new PubKey('00'),
      new Sig('00'),
      1,
      new Bytes(prevTx.serialize()),
      0,
      OP_UNLOCK_FROM_CONTRACT
    ).verify(txContext)
    expect(result.success, result.error).to.be.false
  });

  it('should failed because token input is greater than maxInputLimit', () => {
    verifyTokenContract(maxInputLimit + 1, 1, true, false, 0, 0)
  });

  it('should failed because token output is greater than maxOutputLimit', () => {
    verifyTokenContract(1, maxOutputLimit + 1, true, false, 0, 0)
  });

  it('should failed because input amount is greater then output amount', () => {
    verifyTokenContract(1, 1, true, false, 0, 0, outputTokenAdd=100)
  });

  it('should failed because input amount is less than output amount', () => {
    verifyTokenContract(1, 1, true, false, 0, 0, outputTokenAdd=-100)
  });
});
