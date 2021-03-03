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
console.log('rabin key pair:', rabinPrivateKey, rabinPubKey)

const TokenProto = require('../../deployments/tokenProto')

// make a copy since it will be mutated
let tx
let prevScriptTx
let contractInputIndex
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
const PROTO_FLAG = Buffer.from('oraclesv')
const Token = buildContractClass(compileContract('token.scrypt'))
const RouteCheck = buildContractClass(compileContract('tokenRouteCheck.scrypt'))
//const TokenSell = buildContractClass(compileContract('tokenSell.scrypt'))
//const Token = buildContractClass(loadDesc('token_desc.json'))
//const RouteCheck = buildContractClass(loadDesc('tokenRouteCheck_desc.json'))

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
let genesisHash
let routeCheckCodeHash
let unlockContractCodeHash
let tokenInstance = []
let routeCheckInstance

const maxInputLimit = 8
const maxOutputLimit = 4

const decimalNum = Buffer.from('08', 'hex')

function initContractHash() {
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  const lockingScript = routeCheckCode.lockingScript.toBuffer()
  const code = lockingScript
  routeCheckCodeHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex')
  //TODO:
  unlockContractCodeHash = routeCheckCodeHash
  genesisHash = routeCheckCodeHash
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

function genRouteCheckTx(nOutputs, outputTokenArray) {
  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nOutputs, outputTokenArray)
  prevScriptTx = new bsv.Transaction()
  prevScriptTx.addInput(new bsv.Transaction.Input({
    prevTxId: dummyTxId,
    outputIndex: 0,
    script: ''
  }), bsv.Script.buildPublicKeyHashOut(address1), inputSatoshis)
  const nReceiverBuf = Buffer.alloc(1, 0)
  nReceiverBuf.writeUInt8(nOutputs)
  const routeCheck = new RouteCheck(rabinPubKeyArray)
  const data = Buffer.concat([
    receiverTokenAmountArray,
    recervierArray,
    nReceiverBuf,
    tokenID,
  ])
  routeCheck.setDataPart(data.toString('hex'))
  const routeCheckScript = routeCheck.lockingScript
  prevScriptTx.addOutput(new bsv.Transaction.Output({
    script: routeCheckScript,
    satoshis: inputSatoshis
  }))
  routeCheckInstance = routeCheck
  return prevScriptTx
}

function addInputTokens(nTokenInput, nSatoshiInput, nTokenOutputs, outputTokenAdd) {

  tx = new bsv.Transaction()

  let sumInputTokens = 0
  tokenInstance = []
  for (let i = 0; i < nTokenInput; i++) {
    const bufValue = Buffer.alloc(8, 0)
    bufValue.writeBigUInt64LE(BigInt(outputToken1 + i))
    sumInputTokens += outputToken1 + i
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag,
      decimalNum,
      address1.hashBuffer, // contract script hash
      bufValue, // token amount
      tokenID, 
      tokenType, // type
      PROTO_FLAG
      ])

    const token = new Token(rabinPubKeyArray, new Bytes(routeCheckCodeHash), new Bytes(unlockContractCodeHash), new Bytes(genesisHash))
    token.setDataPart(oracleData.toString('hex'))
    tokenInstance.push(token)
    const tokenScript = token.lockingScript
    tx.addInput(new bsv.Transaction.Input({
      prevTxId: dummyTxId,
      outputIndex: i,
      script: ''
      }), tokenScript, inputSatoshis)
  }

  for (let i = 0; i < nSatoshiInput; i++) {
    tx.addInput(new bsv.Transaction.Input({
      prevTxId: dummyTxId,
      outputIndex: i + nTokenInput,
      script: ''
    }), bsv.Script.buildPublicKeyHashOut(address1), inputSatoshis)
  }

  sumInputTokens += outputTokenAdd
  let outputTokenArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    const bufValue = Buffer.alloc(8, 0)
    if (i == nTokenOutputs - 1) {
      //console.log('output token', i, sumInputTokens)
      bufValue.writeBigUInt64LE(BigInt(sumInputTokens))
      outputTokenArray.push(sumInputTokens)
    } else {
      //console.log('output token', i, i + 1)
      bufValue.writeBigUInt64LE(BigInt(i + 1))
      sumInputTokens -= i + 1
      outputTokenArray.push(i + 1)
    }
  }

  const prevScriptTx = genRouteCheckTx(nTokenOutputs, outputTokenArray)
  const prevScriptTxId = prevScriptTx.id

  contractInputIndex = nTokenInput + nSatoshiInput
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: prevScriptTxId,
    outputIndex: 0,
    script: ''
    }), prevScriptTx.outputs[0].script, inputSatoshis)

  return outputTokenArray
}

function addOutputTokens(nOutputToken, outputTokenArray, changeSatoshi) {
  //console.log('addOutputTokens:', nOutputToken, sumInputTokens, changeSatoshi)
  for (let i = 0; i < nOutputToken; i++) {
    const bufValue = Buffer.alloc(8, 0)
    bufValue.writeBigUInt64LE(BigInt(outputTokenArray[i]))
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag,
      decimalNum,
      address2.hashBuffer, // contract script hash
      bufValue, // token value
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
      ])
    const token = new Token(rabinPubKeyArray, new Bytes(routeCheckCodeHash), new Bytes(unlockContractCodeHash), new Bytes(genesisHash))
    //token.replaceAsmVars(asmVars)
    token.setDataPart(oracleData.toString('hex'))
    tx.addOutput(new bsv.Transaction.Output({
      script: token.lockingScript,
      satoshis: inputSatoshis
    }))
    //console.log('output script:', address2.hashBuffer.toString('hex'), token.lockingScript.toBuffer().toString('hex'), oracleData.toString('hex'))
  }

  if (changeSatoshi > 0) {
    const lockingScript = bsv.Script.buildPublicKeyHashOut(address1)
    tx.addOutput(new bsv.Transaction.Output({
      script: lockingScript,
      satoshis: changeSatoshi 
    }))
    //console.log('changeSatoshi', changeSatoshi, lockingScript.toBuffer().toString('hex'))
  }
  return outputTokenArray
}

function verifyRouteCheck(nTokenInputs, nSatoshiInput, receiverSatoshiArray, changeSatoshi, expected) {

  const txContext = { 
    tx: tx, 
    inputIndex: contractInputIndex, 
    inputSatoshis: inputSatoshis 
  }

  let rabinMsgArray = Buffer.alloc(0)
  let rabinSignArray = Buffer.alloc(0)
  let rabinPaddingArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)
  let inputTokenAmountArray = Buffer.alloc(0)
  let prevouts = Buffer.alloc(0)
  let tokenScript
  for (let i = 0; i < nTokenInputs; i++) {
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(i)
    const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())
    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])

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

    for (let j = 0; j < 3; j++) {
      const rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
      const sigBuf = toBufferLE(rabinSignResult.signature, 128)
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

  for (let i = 0; i < nSatoshiInput; i++) {
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(i + nTokenInputs)
    const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())
    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])
  }

  const indexBuf = Buffer.alloc(4, 0)
  indexBuf.writeUInt32LE(prevScriptOutIndex)
  prevouts = Buffer.concat([
    prevouts,
    Buffer.from([...Buffer.from(prevScriptTx.id, 'hex')].reverse()),
    indexBuf
  ])

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, routeCheckInstance.lockingScript.toASM(), inputSatoshis, inputIndex=contractInputIndex, sighashType=sigtype)

  const result = routeCheckInstance.unlock(
    new SigHashPreimage(toHex(preimage)),
    nTokenInputs,
    new Bytes(tokenScript.toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsgArray.toString('hex')),
    new Bytes(rabinPaddingArray.toString('hex')),
    new Bytes(rabinSignArray.toString('hex')),
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

function verifyTokenContract(nTokenInputs, nOutputs, expectedToken, expectedCheck, nSatoshiInput=0, changeSatoshi=0, outputTokenAdd=0) {
  const outputTokenArray = addInputTokens(nTokenInputs, nSatoshiInput, nOutputs, outputTokenAdd)
  addOutputTokens(nOutputs, outputTokenArray, changeSatoshi)
  //console.log('outputTokenArray:', outputTokenArray)
  for (let i = 0; i < nTokenInputs; i++) {
    verifyOneTokenContract(outputTokenArray, nTokenInputs, nOutputs, nSatoshiInput, i, expectedToken)
  }

  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nOutputs, outputTokenArray)
  verifyRouteCheck(nTokenInputs, nSatoshiInput, receiverSatoshiArray, changeSatoshi, expectedCheck)
}

function verifyOneTokenContract(outputTokenArray, nTokenInputs, nOutputs, nSatoshiInput, inputIndex, expected) {
  //console.log('verifyOneTokenContract:', inputIndex, expected)
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const token = tokenInstance[inputIndex]
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }

  let rabinMsg
  let rabinSign
  let rabinPadding
  let prevouts = Buffer.alloc(0)
  let prevTokenAddress
  let prevTokenAmount
  for (let i = 0; i < nTokenInputs; i++) {
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(i)
    const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())
    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])

    if (i == inputIndex) {
      const scriptBuf = token.lockingScript.toBuffer()
      const scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(scriptBuf))
      prevTokenAddress = TokenProto.getTokenAddress(scriptBuf)
      prevTokenAmount = TokenProto.getTokenAmount(scriptBuf)
      const bufValue = Buffer.alloc(8, 0)
      bufValue.writeBigUInt64LE(BigInt(outputToken1 + i))
      const satoshiBuf = Buffer.alloc(8, 0)
      satoshiBuf.writeBigUInt64LE(BigInt(inputSatoshis))
      rabinMsg = Buffer.concat([
        txidBuf,
        indexBuf,
        satoshiBuf,
        scriptHash,
        txidBuf,
      ])
      const rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
      //console.log('rabinsignature:', msg.toString('hex'), rabinSignResult.paddingByteCount, rabinSignResult.signature)
      rabinSign = rabinSignResult.signature
      rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
    }
  }

  for (let i = 0; i < nSatoshiInput; i++) {
    const indexBuf = Buffer.alloc(4, 0)
    indexBuf.writeUInt32LE(i + nTokenInputs)
    const txidBuf = Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse())
    prevouts = Buffer.concat([
      prevouts,
      txidBuf,
      indexBuf
    ])
  }

  const indexBuf = Buffer.alloc(4, 0)
  indexBuf.writeUInt32LE(prevScriptOutIndex)
  prevouts = Buffer.concat([
    prevouts,
    Buffer.from([...Buffer.from(prevScriptTx.id, 'hex')].reverse()),
    indexBuf
  ])

  let rabinPaddingArray = []
  let rabinSigArray = []
  for (let i = 0; i < 3; i++) {
    rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
    rabinSigArray.push(rabinSign)
  }

  const result = token.route(
    new SigHashPreimage(toHex(preimage)),
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    contractInputIndex,
    new Bytes(prevScriptTx.toString('hex')),
    prevScriptOutIndex,
    nOutputs,
    new Bytes(prevTokenAddress.toString('hex')),
    prevTokenAmount
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
  bufValue.writeBigUInt64LE(BigInt(sellSatoshis * 10))
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

  const token = new Token(rabinPubKeyArray, new Bytes(routeCheckCodeHash), new Bytes(unlockContractCodeHash), new Bytes(genesisHash))
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

  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(address1),
    satoshis: sellSatoshis
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
  const prevouts = Buffer.concat([
    txidBuf,
    indexBuf,
    txidBuf2,
    indexBuf,
  ])
  return {token, preimage, prevouts, prevTx, txContext}
}

describe('Test token contract unlock In Javascript', () => {
  before(() => {
    initContractHash()
  });

  it('should succeed with multi input and output', () => {
    for (let i = 1; i <= 3; i++) {
      for (let j = 1; j <= 3; j++) {
        //console.log("verify token contract:", i, j)
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

  /*it('it should succeed when using unlockFromContract', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext} = unlockFromContract()
    const result = token.unlockFromContract(
      new SigHashPreimage(toHex(preimage)),
      1,
      new Bytes(prevouts.toString('hex')),
      new Bytes(prevTx.serialize()),
      0,
    ).verify(txContext)
    expect(result.success, result.error).to.be.true
  });

  it('it should failed when unlockFromContract with wrong prevTx', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext} = unlockFromContract()
    prevTx.nLockTime = 1
    const result = token.unlockFromContract(
      new SigHashPreimage(toHex(preimage)),
      1,
      new Bytes(prevouts.toString('hex')),
      new Bytes(prevTx.serialize()),
      0,
    ).verify(txContext)
    expect(result.success, result.error).to.be.false
  });

  it('it should failed when unlockFromContract with wrong contract script hash', () => {
    // create the contract tx
    const {token, preimage, prevouts, prevTx, txContext} = unlockFromContract(address2.hashBuffer)
    const result = token.unlockFromContract(
      new SigHashPreimage(toHex(preimage)),
      1,
      new Bytes(prevouts.toString('hex')),
      new Bytes(prevTx.serialize()),
      0,
    ).verify(txContext)
    expect(result.success, result.error).to.be.false
  });*/

  it('should failed because token input is greater than maxInputLimit', () => {
    verifyTokenContract(maxInputLimit + 1, 1, true, false, 0, 0)
  });

  it('should failed because token output is greater than maxOutputLimit', () => {
    verifyTokenContract(1, maxOutputLimit + 1, true, false, 0, 0)
  });

  it('should failed because input output token amount donot match', () => {
    verifyTokenContract(1, 1, true, false, 0, 0, outputTokenAdd=1)
  });
});
