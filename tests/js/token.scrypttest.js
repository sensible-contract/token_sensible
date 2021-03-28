const { expect } = require('chai');
const {
  bsv,
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
  inputSatoshis,
  dummyTxId,
} = require('../../helper');
const {toBufferLE} = require('bigint-buffer')

const {
    privateKey,
    privateKey2,
} = require('../../privateKey');
const Proto = require('../../deployments/protoheader')

const{
  sign,
  } = require("../../rabin/rabin");

const Utils = require("./utils")

const addInput = Utils.addInput
const addOutput = Utils.addOutput
const genContract = Utils.genContract

const rabinPrivateKey = Utils.rabinPrivateKey
const rabinPubKey = Utils.rabinPubKey
const rabinPubKeyArray = [rabinPubKey, rabinPubKey, rabinPubKey]

const TokenProto = require('../../deployments/tokenProto')
const TokenUtil = require('../../deployments/tokenUtil');
const { utils } = require('elliptic');

const OP_TRANSFER = 1
const OP_UNLOCK_FROM_CONTRACT = 2

// make a copy since it will be mutated
let tx
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
const decimalNum = Buffer.from('08', 'hex')

let routeCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash
let genesisScriptBuf
let tokenCodeHash

const maxInputLimit = 3
const maxOutputLimit = 3

let Token, RouteCheck, UnlockContractCheck, TokenSell

function initContract() {
  const use_desc = false
  Genesis = genContract('tokenGenesis', use_desc)
  Token = genContract('token', use_desc)
  RouteCheck = genContract('tokenRouteCheck', use_desc)
  UnlockContractCheck = genContract('tokenUnlockContractCheck', use_desc)
  TokenSell = genContract('tokenSell', true)
}

function createTokenGenesisContract() {
  const issuerPubKey = privateKey.publicKey
  const genesis = new Genesis(new PubKey(toHex(issuerPubKey)), rabinPubKeyArray)
  const oracleData = Buffer.concat([
    tokenName,
    tokenSymbol,
    genesisFlag, 
    decimalNum,
    Buffer.alloc(20, 0), // address
    Buffer.alloc(8, 0), // token value
    tokenID, // script code hash
    tokenType, // type
    PROTO_FLAG
  ])
  genesis.setDataPart(oracleData.toString('hex'))
  return genesis
}

function initContractHash() {
  const routeCheckCode = new RouteCheck(rabinPubKeyArray)
  let code = routeCheckCode.lockingScript.toBuffer()
  const routeCheckCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  routeCheckCodeHashArray = [routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash]

  const unlockContract = new UnlockContractCheck(rabinPubKeyArray)
  code = unlockContract.lockingScript.toBuffer()
  const unlockContractCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]

  const genesis = createTokenGenesisContract()
  genesisScriptBuf = genesis.lockingScript.toBuffer()
  genesisHash = bsv.crypto.Hash.sha256ripemd160(genesisScriptBuf).toString('hex')
  //console.log("genesisHash:", genesisHash)

  const tokenContract = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash))
  code = tokenContract.lockingScript.toBuffer()
  tokenCodeHash = bsv.crypto.Hash.sha256ripemd160(code)
}

function createTokenContract(addressBuf, amount) {
  const token = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash))
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
  return [routeCheck, tx]
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

function createUnlockContractCheck(nTokenOutputs, tokenOutputAmounts, tokenOutputAddress, tid=tokenID) {
  const unlockContractCheck = new UnlockContractCheck(rabinPubKeyArray)
  let receiverTokenAmountArray = Buffer.alloc(0)
  let recervierArray = Buffer.alloc(0)
  let nReceiverBuf = TokenUtil.getUInt8Buf(nTokenOutputs)
  for (let i = 0; i < nTokenOutputs; i++) {
    recervierArray = Buffer.concat([recervierArray, tokenOutputAddress[i]])
    receiverTokenAmountArray = Buffer.concat([
      receiverTokenAmountArray, 
      TokenUtil.getUInt64Buf(tokenOutputAmounts[i])
    ])
  }
  const data = Buffer.concat([
    receiverTokenAmountArray,
    recervierArray,
    nReceiverBuf,
    tokenCodeHash,
    Buffer.from(tid, 'hex'),
  ])
  unlockContractCheck.setDataPart(data.toString('hex'))

  const tx = new bsv.Transaction()
  addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
  tx.addOutput(new bsv.Transaction.Output({
    script: unlockContractCheck.lockingScript,
    satoshis: inputSatoshis
  }))

  return [unlockContractCheck, tx]
}

function verifyRouteCheck(tx, prevouts, routeCheck, tokenInstance, nTokenInput, receiverSatoshiArray, changeSatoshi, inputIndex, expected) {

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
  const preimage = getPreimage(tx, routeCheck.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const result = routeCheck.unlock(
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
    verifyOneTokenContract(tx, [0, 1], prevouts, tokenInstance[i], nTokenOutputs, i, contractInputIndex, routeCheckTx, 0, 0, Buffer.alloc(1), 0, OP_TRANSFER, expectedToken)
  }

  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nTokenOutputs, outputTokenArray)
  verifyRouteCheck(tx, prevouts, routeCheck, tokenInstance, nTokenInput, receiverSatoshiArray, changeSatoshi, contractInputIndex, expectedCheck)
}

function verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nOutputs, inputIndex, checkInputIndex, checkScriptTx, checkScriptTxOutputIndex, lockContractInputIndex, lockContractTx, lockContractTxOutIndex, op, expected) {
  //console.log('verifyOneTokenContract:', inputIndex, expected)
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }

  const prevTokenAddress = address2.hashBuffer
  const prevTokenAmount = 1999
  const scriptBuf = TokenProto.getNewTokenScript(token.lockingScript.toBuffer(), prevTokenAddress, prevTokenAmount)
  const [rabinMsg, rabinPaddingArray, rabinSigArray] = Utils.createRabinMsg(dummyTxId, inputIndex, inputSatoshis, scriptBuf, dummyTxId)

  const result = token.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    checkInputIndex,
    new Bytes(checkScriptTx.toString('hex')),
    checkScriptTxOutputIndex,
    nOutputs,
    new Bytes(prevTokenAddress.toString('hex')),
    prevTokenAmount,
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    lockContractInputIndex,
    new Bytes(lockContractTx.toString('hex')),
    lockContractTxOutIndex,
    op
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
  //return result
}

function createTokenSellContract(sellSatoshis) {
  const tx = new bsv.Transaction()
  addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])
  const tokenSell = new TokenSell(new Ripemd160(address1.hashBuffer.toString('hex')), sellSatoshis)
  const sellScript = tokenSell.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: sellScript,
    satoshis: inputSatoshis
  }))

  return [tokenSell, tx]
}

function unlockFromContract(args) {

  const tokenExpected = args.tokenExpected
  const checkExpected = args.checkExpected
  const nLockTime = args.nLockTime
  let rabinPubKeyIndexArray = args.rabinPubKeyIndexArray
  if (rabinPubKeyIndexArray === undefined) {
    rabinPubKeyIndexArray = [0, 1]
  }
  const sellSatoshis = 10000
  let prevouts = []
  const tx = new bsv.Transaction()

  const [tokenSell, tokenSellTx] = createTokenSellContract(sellSatoshis)
  let scriptHash = args.scriptHash
  if (scriptHash === undefined) {
    scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenSell.lockingScript.toBuffer()))
  }
  addInput(tx, tokenSell.lockingScript, 1, prevouts, prevTxId=tokenSellTx.id)

  const inputTokenAmount = sellSatoshis * 10
  const token = createTokenContract(scriptHash, inputTokenAmount)
  const tokenScript = token.lockingScript

  addInput(tx, token.lockingScript, 0, prevouts)

  const nTokenOutputs = 1
  const outputTokenArray = [inputTokenAmount]
  const outputTokenAddress = [address2.hashBuffer]
  const [unlockContractCheck, unlockContractCheckTx] = createUnlockContractCheck(nTokenOutputs, outputTokenArray, outputTokenAddress)
  addInput(tx, unlockContractCheck.lockingScript, 2, prevouts, prevTxId=unlockContractCheckTx.id)

  prevouts = Buffer.concat(prevouts)

  addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), sellSatoshis)

  const tokenScriptBuffer = TokenProto.getNewTokenScript(tokenScript.toBuffer(), address2.hashBuffer, inputTokenAmount)
  addOutput(tx, bsv.Script.fromBuffer(tokenScriptBuffer), inputSatoshis)

  Utils.verifyTokenUnlockContractCheck(tx, unlockContractCheck, 2, 1, prevouts, [1], [1], isBurn=false, expected=checkExpected)

  tokenSellTx.nLockTime = nLockTime
  verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, 1, 1, 2, unlockContractCheckTx, 0, 0, tokenSellTx, 0, OP_UNLOCK_FROM_CONTRACT, tokenExpected)
}

function simpleRouteUnlock(preUtxoId, preUtxoOutputIndex, scriptBuf, expected=true, wrongRabin=false, wrongRouteCheck=0) {
  const tokenInputAmount = 100
  const token = createTokenContract(address1.hashBuffer, tokenInputAmount)

  const tx = new bsv.Transaction()
  let prevouts = []
  addInput(tx, token.lockingScript, 0, prevouts)
  let routeCheck, routeCheckTx
  if (wrongRouteCheck) {
    [routeCheck, routeCheckTx] = createUnlockContractCheck(1, [tokenInputAmount], [address1.hashBuffer])
  } else {
    [routeCheck, routeCheckTx] = createRouteCheckContract(1, [tokenInputAmount])
  }
  const contractInputIndex = 1
  addInput(tx, routeCheck.lockingScript, contractInputIndex, prevouts, prevTxId=routeCheckTx.id)
  prevouts = Buffer.concat(prevouts)

  addOutput(tx, token.lockingScript, inputSatoshis)

  let inputIndex = 0
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  let [rabinMsg, rabinPaddingArray, rabinSigArray] = Utils.createRabinMsg(preUtxoId, preUtxoOutputIndex, inputSatoshis, scriptBuf, dummyTxId)
  if (wrongRabin) {
    rabinSigArray = [0, 0]
  }
  //console.log("simpleRouteUnlock:", scriptBuf.toString('hex'), rabinMsg.toString('hex'))

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }
  const result = token.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    [0, 1],
    contractInputIndex,
    new Bytes(routeCheckTx.toString('hex')),
    0,
    1,
    new Bytes('00'),
    0,
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    0,
    new Bytes('00'),
    0,
    OP_TRANSFER
  ).verify(txContext)
  if (expected) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
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

  it('should failed when token is unlock from wrong rabin sig', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20), expected=false, wrongRabin=true)
  })

  it('should failed when token is unlock from wrong tokenRouteCheck', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20), expected=false, wrongRabin=false, wrongRouteCheck=true)
  })

  it('should succeed when token is generated from genesis', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20))
    simpleRouteUnlock(dummyTxId, 1, genesisScriptBuf)
  })

  it('should failed when token is unlock from wrong genesis', () => {
    simpleRouteUnlock(dummyTxId, 1, Buffer.alloc(20), expected=false)
  })

  it('it should succeed when using unlockFromContract', () => {
    // create the contract tx
    const args = {
      nLockTime: 0,
      tokenExpected: true,
      checkExpected: true,
    }
    unlockFromContract(args)
  });

  it('it should failed when unlockFromContract with wrong lockContractTx', () => {
    const args = {
      nLockTime: 1,
      tokenExpected: false,
      checkExpected: true,
    }
    unlockFromContract(args)
  });

  it('it should failed when unlockFromContract with wrong contract script hash', () => {
    const args = {
      scriptHash: address2.hashBuffer,
      nLockTime: 0,
      tokenExpected: false,
      checkExpected: true,
    }
    unlockFromContract(args)
  });

  it('it should failed when pass same rabinPubKey index', () => {
    const args = {
      scriptHash: address2.hashBuffer,
      nLockTime: 0,
      tokenExpected: false,
      checkExpected: true,
      rabinPubKeyIndexArray: [1, 1]
    }
    unlockFromContract(args)
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
