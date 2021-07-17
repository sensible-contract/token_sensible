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

const {
    privateKey,
    privateKey2,
} = require('../../privateKey');
const Proto = require('../../deployments/protoheader')
const TokenProto = require('../../deployments/tokenProto')
const TokenUtil = require('../../deployments/tokenUtil');
const Common = require('../../deployments/common')
const toBufferLE = Common.toBufferLE

const{
  sign,
  } = require("../../rabin/rabin");

const Utils = require("./utils");

const addInput = Utils.addInput
const addOutput = Utils.addOutput
const genContract = Utils.genContract

const rabinPubKeyHashArray = Common.rabinPubKeyHashArray
const rabinPubKeyVerifyArray =  Common.rabinPubKeyVerifyArray

const OP_TRANSFER = 1
const OP_UNLOCK_FROM_CONTRACT = 2

// make a copy since it will be mutated
const outputToken1 = 100

const tokenName = Buffer.alloc(20, 0)
tokenName.write('test token name')
const tokenSymbol = Buffer.alloc(10, 0)
tokenSymbol.write('ttn')
const genesisFlag = TokenUtil.getUInt8Buf(1)
const nonGenesisFlag = TokenUtil.getUInt8Buf(0)
const tokenType = TokenUtil.getUInt32Buf(1)
const PROTO_FLAG = Proto.PROTO_FLAG

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()
const sensibleID = Buffer.concat([
  TokenUtil.getTxIdBuf(dummyTxId),
  TokenUtil.getUInt32Buf(0)
])
const sensibleID2 = Buffer.concat([
  TokenUtil.getTxIdBuf(dummyTxId),
  TokenUtil.getUInt32Buf(1)
])
let tokenID
const tokenID2 = Buffer.alloc(20, 0)
const decimalNum = TokenUtil.getUInt8Buf(8)

let transferCheckCodeHashArray
let unlockContractCodeHashArray
let genesisHash
let genesisScriptBuf
let tokenCodeHash

const maxInputLimit = 3
const maxOutputLimit = 3

let Token, TransferCheck, UnlockContractCheck, TokenSell

function initContract() {
  const use_desc = false
  const use_release = false
  Genesis = genContract('tokenGenesis', use_desc, use_release)
  Token = genContract('token', use_desc, use_release)
  TransferCheck = genContract('tokenTransferCheck', use_desc, use_release)
  UnlockContractCheck = genContract('tokenUnlockContractCheck', use_desc, use_release)
  TokenSell = genContract('tokenSell', use_desc, use_release)
}

function createTokenGenesisContract() {
  const issuerPubKey = privateKey.publicKey
  const genesis = new Genesis(new PubKey(toHex(issuerPubKey)))
  const oracleData = Buffer.concat([
    tokenName,
    tokenSymbol,
    genesisFlag, 
    decimalNum,
    Buffer.alloc(20, 0), // address
    Buffer.alloc(8, 0), // token value
    Buffer.alloc(20, 0), // genesisHash
    Common.rabinPubKeyHashArrayHash,
    sensibleID,
    tokenType,
    PROTO_FLAG
  ])
  genesis.setDataPart(oracleData.toString('hex'))
  return genesis
}

function initContractHash() {
  const transferCheckCode = new TransferCheck()
  let code = transferCheckCode.lockingScript.toBuffer()
  const transferCheckCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  transferCheckCodeHashArray = [transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash]

  const unlockContract = new UnlockContractCheck()
  code = unlockContract.lockingScript.toBuffer()
  const unlockContractCodeHash = new Bytes(Buffer.from(bsv.crypto.Hash.sha256ripemd160(code)).toString('hex'))
  unlockContractCodeHashArray = [unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash, unlockContractCodeHash]

  const genesis = createTokenGenesisContract()
  genesisScriptBuf = genesis.lockingScript.toBuffer()
  genesisHash = bsv.crypto.Hash.sha256ripemd160(genesisScriptBuf)
  const tokenIDData =  Buffer.concat([
    genesisHash,
    Common.rabinPubKeyHashArrayHash,
    sensibleID,
  ])
  tokenID = bsv.crypto.Hash.sha256ripemd160(tokenIDData)
  //console.log("genesisHash:", genesisHash)

  const tokenContract = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
  code = tokenContract.lockingScript.toBuffer()
  tokenCodeHash = bsv.crypto.Hash.sha256ripemd160(code)
}

function createTokenContract(addressBuf, amount) {
  const token = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
  const data = Buffer.concat([
    tokenName,
    tokenSymbol,
    nonGenesisFlag, 
    decimalNum,
    addressBuf,
    TokenUtil.getUInt64Buf(amount),
    genesisHash,
    Common.rabinPubKeyHashArrayHash,
    Buffer.from(sensibleID, 'hex'),
    tokenType,
    PROTO_FLAG
  ])
  token.setDataPart(data.toString('hex'))
  return token
}

function createTransferCheckContract(nTokenInputs, nOutputs, outputTokenArray, tid=tokenID, tcHash=tokenCodeHash) {
  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nOutputs, outputTokenArray)
  const tx = new bsv.Transaction()
  addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), 0, [])

  const transferCheck = new TransferCheck()
  const data = Buffer.concat([
    TokenUtil.getUInt32Buf(nTokenInputs),
    receiverTokenAmountArray,
    recervierArray,
    TokenUtil.getUInt32Buf(nOutputs),
    tcHash,
    tid,
  ])
  transferCheck.setDataPart(data.toString('hex'))
  const transferCheckScript = transferCheck.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: transferCheckScript,
    satoshis: inputSatoshis
  }))
  return [transferCheck, tx]
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

function createUnlockContractCheck(tokenInputIndexArray, nTokenOutputs, tokenOutputAmounts, tokenOutputAddress, tid=tokenID, tcHash=tokenCodeHash) {
  const unlockContractCheck = new UnlockContractCheck()

  const nTokenInputs = tokenInputIndexArray.length
  let tokenInputIndexBytes = Buffer.alloc(0)
  for (let i = 0; i < nTokenInputs; i++) {
    tokenInputIndexBytes = Buffer.concat([tokenInputIndexBytes, TokenUtil.getUInt32Buf(tokenInputIndexArray[i])]);
  }

  let receiverTokenAmountArray = Buffer.alloc(0)
  let recervierArray = Buffer.alloc(0)
  for (let i = 0; i < nTokenOutputs; i++) {
    recervierArray = Buffer.concat([recervierArray, tokenOutputAddress[i]])
    receiverTokenAmountArray = Buffer.concat([
      receiverTokenAmountArray, 
      TokenUtil.getUInt64Buf(tokenOutputAmounts[i])
    ])
  }
  const data = Buffer.concat([
    tokenInputIndexBytes,
    TokenUtil.getUInt32Buf(nTokenInputs),
    receiverTokenAmountArray,
    recervierArray,
    TokenUtil.getUInt32Buf(nTokenOutputs),
    tcHash,
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

function verifyTransferCheck(tx, rabinPubKeyIndexArray, prevouts, transferCheck, tokenInstance, nTokenInputs, receiverSatoshiArray, changeSatoshi, inputIndex, expected) {

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
  for (let i = 0; i < nTokenInputs; i++) {
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

    for (let j = 0; j < Utils.oracleVerifyNum; j++) {
      const idx = Common.rabinPubKeyIndexArray[j]
      const rabinPrivateKey = Common.rabinPrivateKeys[idx]
      const rabinPubKey = Common.rabinPubKeyArray[idx]
      const rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
      let padding = Buffer.concat([
        TokenUtil.getUInt16Buf(rabinSignResult.paddingByteCount),
        Buffer.alloc(rabinSignResult.paddingByteCount)
      ])
      rabinPaddingArray = Buffer.concat([
        rabinPaddingArray,
        padding
      ])

      const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
      rabinSignArray = Buffer.concat([rabinSignArray, sigBuf])
    }
  }

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, transferCheck.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  const result = transferCheck.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(tokenScript.toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsgArray.toString('hex')),
    new Bytes(rabinPaddingArray.toString('hex')),
    new Bytes(rabinSignArray.toString('hex')),
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    new Bytes(rabinPubKeyHashArray.toString('hex')),
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    new Bytes(receiverSatoshiArray.toString('hex')),
    changeSatoshi,
    new Ripemd160(address1.hashBuffer.toString('hex')),
    new Bytes('')
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
}

function verifyTokenTransfer(nTokenInputs, nTokenOutputs, nSatoshiInput, changeSatoshi, args) {
  const tx =  new bsv.Transaction()
  let prevouts = []

  let sumInputTokens = 0
  let tokenInstance = []
  let tokenScriptBuf
  // add token input
  for (let i = 0; i < nTokenInputs; i++) {
    const token = createTokenContract(address1.hashBuffer, outputToken1 + i)
    tokenInstance.push(token)
    tokenScriptBuf = token.lockingScript.toBuffer()
    sumInputTokens += outputToken1 + i
    addInput(tx, token.lockingScript, i, prevouts)
  }

  // add bsv input
  for (let i = 0; i < nSatoshiInput; i++) {
    addInput(tx, bsv.Script.buildPublicKeyHashOut(address1), i + nTokenInputs, prevouts)
  }

  if (args.outputTokenAdd !== undefined) {
    sumInputTokens += args.outputTokenAdd
  }
  let outputTokenArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    if (i == nTokenOutputs - 1) {
      outputTokenArray.push(sumInputTokens)
    } else {
      sumInputTokens -= i + 1
      outputTokenArray.push(i + 1)
    }
  }

  // add tokenTransferCheckContract
  let tid = tokenID
  if (args.wrongTokenID) {
    tid = tokenID2 
  }
  let tcHash = tokenCodeHash
  if (args.wrongTokenCodeHash) {
    tcHash = Buffer.alloc(20, 0)
  }

  let routeNTokenInputs = nTokenInputs
  if (args.wrongNSenders) {
    routeNTokenInputs = nTokenInputs - 1
  }
  const [transferCheck, transferCheckTx] = createTransferCheckContract(routeNTokenInputs, nTokenOutputs, outputTokenArray, tid=tid, tcHash=tcHash)
  const contractInputIndex = nTokenInputs + nSatoshiInput
  addInput(tx, transferCheck.lockingScript, 0, prevouts, prevTxId=transferCheckTx.id)

  prevouts = Buffer.concat(prevouts)

  // output
  for (let i = 0; i < nTokenOutputs; i++) {
    const scriptBuf = TokenProto.getNewTokenScript(tokenScriptBuf, address2.hashBuffer, outputTokenArray[i])
    addOutput(tx, bsv.Script.fromBuffer(scriptBuf))
  }

  if (changeSatoshi > 0) {
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), changeSatoshi)
  }

  let rabinPubKeyIndexArray = Utils.rabinPubKeyIndexArray
  if (args.wrongRabinPubKeyIndex) {
    rabinPubKeyIndexArray = Array(Utils.oracleVerifyNum).fill(0)
  }

  //console.log('outputTokenArray:', outputTokenArray)
  for (let i = 0; i < nTokenInputs; i++) {
    if (typeof(args.tokenExpected) === 'boolean') {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, tokenInstance[i], nTokenOutputs, i, i, contractInputIndex, transferCheckTx, 0, Buffer.alloc(1), OP_TRANSFER, args.tokenExpected)
    } else {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, tokenInstance[i], nTokenOutputs, i, i, contractInputIndex, transferCheckTx, 0, Buffer.alloc(1), OP_TRANSFER, args.tokenExpected[i])
    }
  }

  const {recervierArray, receiverTokenAmountArray, receiverSatoshiArray} = genReceiverData(nTokenOutputs, outputTokenArray)
  verifyTransferCheck(tx, rabinPubKeyIndexArray, prevouts, transferCheck, tokenInstance, nTokenInputs, receiverSatoshiArray, changeSatoshi, contractInputIndex, args.checkExpected)
}

function verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nOutputs, inputIndex, tokenInputIndex, checkInputIndex, checkScriptTx, lockContractInputIndex, lockContractTx, op, expected) {
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
  const [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(dummyTxId, inputIndex, inputSatoshis, scriptBuf, dummyTxId)

  const result = token.unlock(
    new SigHashPreimage(toHex(preimage)),
    tokenInputIndex,
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    new Bytes(rabinPubKeyHashArray.toString('hex')),
    checkInputIndex,
    new Bytes(checkScriptTx.toString('hex')),
    nOutputs,
    new Bytes(prevTokenAddress.toString('hex')),
    prevTokenAmount,
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    lockContractInputIndex,
    new Bytes(lockContractTx.toString('hex')),
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

function unlockFromContractFake(args) {

  const nTokenInputs = 1
  const nTokenOutputs = 1
  const nOtherOutputs = 1
  const tokenExpected = args.tokenExpected
  const checkExpected = args.checkExpected
  let rabinPubKeyIndexArray = Utils.rabinPubKeyIndexArray
  if (args.wrongRabinPubKeyIndex) {
    rabinPubKeyIndexArray = Array(Utils.oracleVerifyNum).fill(0)
  }
  const sellSatoshis = 10000
  let prevouts = []
  const tx = new bsv.Transaction()

  const [tokenSell, tokenSellTx] = createTokenSellContract(sellSatoshis)
  let scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenSell.lockingScript.toBuffer()))
  if (args.scriptHash) {
    scriptHash = args.scriptHash 
  }

  addInput(tx, tokenSell.lockingScript, 0, prevouts, prevTxId=tokenSellTx.id)

  let tokenInstance = []
  let tokenScript
  let tokenInputIndexArray = []
  let sumInputTokenAmount = 0
  for (let i = 0; i < nTokenInputs; i++) {
    const inputTokenAmount = sellSatoshis * 10
    let address
    if (Array.isArray(scriptHash)) {
      address = scriptHash[i]
    } else {
      address = scriptHash
    }
    const token = createTokenContract(address, inputTokenAmount)
    tokenInstance.push(token)
    tokenScript = token.lockingScript
    addInput(tx, token.lockingScript, i + 1, prevouts)
    tokenInputIndexArray.push(i + 1)
    sumInputTokenAmount += inputTokenAmount
  }

  let outputTokenAddress = []
  let outputTokenArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    outputTokenAddress.push(address2.hashBuffer)
    if (i == nTokenOutputs - 1) {
      if (args.outputTokenAdd !== undefined) {
        outputTokenArray.push(sumInputTokenAmount + args.outputTokenAdd)
      } else {
        outputTokenArray.push(sumInputTokenAmount)
      }
    } else {
      outputTokenArray.push(1)
      sumInputTokenAmount -= 1
    }
  }
  let tid = tokenID
  if (args.wrongTokenID) {
    tid = tokenID2
  }
  let tcHash = tokenCodeHash
  if (args.wrongTokenCodeHash) {
    tcHash = Buffer.alloc(20, 0)
  }

  if (args.wrongNSenders) {
    tokenInputIndexArray.pop()
  }
  const [unlockContractCheck, unlockContractCheckTx] = createUnlockContractCheck(tokenInputIndexArray, nTokenOutputs, outputTokenArray, outputTokenAddress, tid=tid, tcHash=tcHash)
  addInput(tx, unlockContractCheck.lockingScript, 0, prevouts, prevTxId=unlockContractCheckTx.id)

  prevouts = Buffer.concat(prevouts)

  let tokenOutputIndexArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    const tokenScriptBuffer = TokenProto.getNewTokenScript(tokenScript.toBuffer(), outputTokenAddress[i], outputTokenArray[i])
    addOutput(tx, bsv.Script.fromBuffer(tokenScriptBuffer), inputSatoshis)
    tokenOutputIndexArray.push(i)
  }

  // add fake output
  addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), sellSatoshis)
  const tokenScriptBuffer = TokenProto.getNewTokenScript(tokenScript.toBuffer(), outputTokenAddress[0], 199999)
  addOutput(tx, bsv.Script.fromBuffer(tokenScriptBuffer), inputSatoshis)
  for (let i = 0; i < nOtherOutputs; i++) {
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), sellSatoshis)
  }


  Utils.verifyTokenUnlockContractCheck(tx, unlockContractCheck, nTokenInputs + 1, prevouts, tokenInputIndexArray, tokenOutputIndexArray, expected=checkExpected, fake=true)

  if (args.wrongLockContractTx) {
    tokenSellTx.nLockTime = 1
  }
  for (let i = 0; i < nTokenInputs; i++) {
    const token = tokenInstance[i]
    if (typeof(tokenExpected) === 'boolean') {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nTokenOutputs, i + 1, i, nTokenInputs + 1, unlockContractCheckTx, 0, tokenSellTx, OP_UNLOCK_FROM_CONTRACT, tokenExpected)
    } else {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nTokenOutputs, i + 1, i, nTokenInputs + 1, unlockContractCheckTx, 0, tokenSellTx, OP_UNLOCK_FROM_CONTRACT, tokenExpected[i])
    }
  }
}

function unlockFromContract(nTokenInputs, nTokenOutputs, nOtherOutputs, args) {

  const tokenExpected = args.tokenExpected
  const checkExpected = args.checkExpected
  let rabinPubKeyIndexArray = Utils.rabinPubKeyIndexArray
  if (args.wrongRabinPubKeyIndex) {
    rabinPubKeyIndexArray = Array(Utils.oracleVerifyNum).fill(0)
  }
  const sellSatoshis = 10000
  let prevouts = []
  const tx = new bsv.Transaction()

  const [tokenSell, tokenSellTx] = createTokenSellContract(sellSatoshis)
  let scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenSell.lockingScript.toBuffer()))
  if (args.scriptHash) {
    scriptHash = args.scriptHash 
  }

  addInput(tx, tokenSell.lockingScript, 0, prevouts, prevTxId=tokenSellTx.id)

  let tokenInstance = []
  let tokenScript
  let tokenInputIndexArray = []
  let sumInputTokenAmount = 0
  for (let i = 0; i < nTokenInputs; i++) {
    const inputTokenAmount = sellSatoshis * 10
    let address
    if (Array.isArray(scriptHash)) {
      address = scriptHash[i]
    } else {
      address = scriptHash
    }
    const token = createTokenContract(address, inputTokenAmount)
    tokenInstance.push(token)
    tokenScript = token.lockingScript
    addInput(tx, token.lockingScript, i + 1, prevouts)
    tokenInputIndexArray.push(i + 1)
    sumInputTokenAmount += inputTokenAmount
  }

  let outputTokenAddress = []
  let outputTokenArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    outputTokenAddress.push(address2.hashBuffer)
    if (i == nTokenOutputs - 1) {
      if (args.outputTokenAdd !== undefined) {
        outputTokenArray.push(sumInputTokenAmount + args.outputTokenAdd)
      } else {
        outputTokenArray.push(sumInputTokenAmount)
      }
    } else {
      outputTokenArray.push(1)
      sumInputTokenAmount -= 1
    }
  }
  let tid = tokenID
  if (args.wrongTokenID) {
    tid = tokenID2
  }
  let tcHash = tokenCodeHash
  if (args.wrongTokenCodeHash) {
    tcHash = Buffer.alloc(20, 0)
  }

  if (args.wrongNSenders) {
    tokenInputIndexArray.pop()
  }
  const [unlockContractCheck, unlockContractCheckTx] = createUnlockContractCheck(tokenInputIndexArray, nTokenOutputs, outputTokenArray, outputTokenAddress, tid=tid, tcHash=tcHash)
  addInput(tx, unlockContractCheck.lockingScript, 0, prevouts, prevTxId=unlockContractCheckTx.id)

  prevouts = Buffer.concat(prevouts)

  for (let i = 0; i < nOtherOutputs; i++) {
    addOutput(tx, bsv.Script.buildPublicKeyHashOut(address1), sellSatoshis)
  }

  let tokenOutputIndexArray = []
  for (let i = 0; i < nTokenOutputs; i++) {
    const tokenScriptBuffer = TokenProto.getNewTokenScript(tokenScript.toBuffer(), outputTokenAddress[i], outputTokenArray[i])
    addOutput(tx, bsv.Script.fromBuffer(tokenScriptBuffer), inputSatoshis)
    tokenOutputIndexArray.push(i + nOtherOutputs)
  }

  Utils.verifyTokenUnlockContractCheck(tx, unlockContractCheck, nTokenInputs + 1, prevouts, tokenInputIndexArray, tokenOutputIndexArray, expected=checkExpected)

  if (args.wrongLockContractTx) {
    tokenSellTx.nLockTime = 1
  }
  for (let i = 0; i < nTokenInputs; i++) {
    const token = tokenInstance[i]
    if (typeof(tokenExpected) === 'boolean') {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nTokenOutputs, i + 1, i, nTokenInputs + 1, unlockContractCheckTx, 0, tokenSellTx, OP_UNLOCK_FROM_CONTRACT, tokenExpected)
    } else {
      verifyOneTokenContract(tx, rabinPubKeyIndexArray, prevouts, token, nTokenOutputs, i + 1, i, nTokenInputs + 1, unlockContractCheckTx, 0, tokenSellTx, OP_UNLOCK_FROM_CONTRACT, tokenExpected[i])
    }
  }
}

function simpleRouteUnlock(preUtxoId, preUtxoOutputIndex, scriptBuf, options={}) {
  const tokenInputAmount = 100
  const token = createTokenContract(address1.hashBuffer, tokenInputAmount)

  const tx = new bsv.Transaction()
  let prevouts = []
  addInput(tx, token.lockingScript, 0, prevouts)
  let transferCheck, transferCheckTx
  if (options.wrongTransferCheck) {
    [transferCheck, transferCheckTx] = createUnlockContractCheck([0], 1, [tokenInputAmount], [address1.hashBuffer])
  } else {
    [transferCheck, transferCheckTx] = createTransferCheckContract(1, 1, [tokenInputAmount])
  }
  let contractInputIndex = 1
  if (options.wrongCheckContractInputIndex) {
    contractInputIndex = 0
  }
  addInput(tx, transferCheck.lockingScript, 0, prevouts, prevTxId=transferCheckTx.id)
  prevouts = Buffer.concat(prevouts)

  addOutput(tx, token.lockingScript, inputSatoshis)

  let inputIndex = 0
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, token.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)

  let [rabinMsg, rabinPaddingArray, rabinSigArray] = Common.createRabinMsg(preUtxoId, preUtxoOutputIndex, inputSatoshis, scriptBuf, dummyTxId)
  if (options.wrongRabin) {
    rabinSigArray = Array(Utils.oracleVerifyNum).fill(0)
  }
  //console.log("simpleRouteUnlock:", scriptBuf.toString('hex'), rabinMsg.toString('hex'))

  const txContext = { 
    tx: tx, 
    inputIndex: inputIndex, 
    inputSatoshis: inputSatoshis 
  }
  const result = token.unlock(
    new SigHashPreimage(toHex(preimage)),
    0,
    new Bytes(prevouts.toString('hex')),
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    Utils.rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    new Bytes(rabinPubKeyHashArray.toString('hex')),
    contractInputIndex,
    new Bytes(transferCheckTx.toString('hex')),
    1,
    new Bytes('00'),
    0,
    new PubKey(toHex(privateKey.publicKey)),
    new Sig(toHex(sig)),
    0,
    new Bytes('00'),
    OP_TRANSFER
  ).verify(txContext)
  if (options.expected === false) {
    expect(result.success, result.error).to.be.false
  } else {
    expect(result.success, result.error).to.be.true
  }
}

describe('Test token contract unlock In Javascript', () => {
  before(() => {
    initContract()
    initContractHash()
  });

  it('should succeed with multi input and output', () => {
    args = {
      tokenExpected: true,
      checkExpected: true,
    }
    for (let i = 1; i <= 3; i++) {
      for (let j = 1; j <= 3; j++) {
        verifyTokenTransfer(i, j, 0, 0, args)
      }
    }
    verifyTokenTransfer(maxInputLimit, maxOutputLimit, 0, 0, args)
  });

  it('should succeed with bsv input', () => {
    args = {
      tokenExpected: true,
      checkExpected: true,
    }
    for (let i = 1; i <= 3; i++) {
      for (let j = 1; j <= 3; j++) {
        //console.log("verify token contract:", i, j)
        verifyTokenTransfer(i, j, 2, 1000, args)
      }
    }
    verifyTokenTransfer(maxInputLimit, maxOutputLimit, 2, 1000, args)
  });

  it('should failed because token input number is greater than transferCheck nSenders', () => {
    args = {
      tokenExpected: [true, false],
      checkExpected: false,
      wrongNSenders: true,
    }
    verifyTokenTransfer(2, 1, 0, 0, args)
  });

  it('should failed because token input is greater than maxInputLimit', () => {
    args = {
      tokenExpected: true,
      checkExpected: false,
    }
    verifyTokenTransfer(maxInputLimit + 1, 1, 0, 0, args)
  });

  it('should failed because token output is greater than maxOutputLimit', () => {
    args = {
      tokenExpected: true,
      checkExpected: false,
    }
    verifyTokenTransfer(1, maxOutputLimit + 1, 0, 0, args)
  });

  it('should failed because input amount is greater then output amount', () => {
    args = {
      tokenExpected: true,
      checkExpected: false,
      outputTokenAdd: 100,
    }
    verifyTokenTransfer(1, 1, 0, 0, args)
  });

  it('should failed because input amount is less than output amount', () => {
    args = {
      tokenExpected: true,
      checkExpected: false,
      outputTokenAdd: -100,
    }
    verifyTokenTransfer(1, 1, 0, 0, args)
  });

  it('should failed with wrong tokenID in routeAmountCheck', () => {
    args = {
      tokenExpected: false,
      checkExpected: false,
      wrongTokenID: true,
    }
    verifyTokenTransfer(1, 1, 0, 0, args)
  })

  it('should failed with wrong token code hash in routeAmountCheck', () => {
    args = {
      tokenExpected: false,
      checkExpected: false,
      wrongTokenCodeHash: true,
    }
    verifyTokenTransfer(1, 1, 0, 0, args)
  })

  it('should failed with wrong rabin pubkey index array in routeAmountCheck', () => {
    args = {
      tokenExpected: false,
      checkExpected: false,
      wrongRabinPubKeyIndex: true,
    }
    verifyTokenTransfer(1, 1, 0, 0, args)
  })

  it('should failed when token is unlock from wrong rabin sig', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20), {expected: false, wrongRabin: true})
  })

  it('should failed when token is unlock from wrong tokenTransferCheck', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20), {expected: false, wrongTransferCheck: true})
  })

  it('should succeed when token is generated from genesis', () => {
    simpleRouteUnlock(dummyTxId, 0, Buffer.alloc(20))
    simpleRouteUnlock(dummyTxId, 1, genesisScriptBuf)
  })

  it('should failed when token is unlock from wrong genesis', () => {
    simpleRouteUnlock(dummyTxId, 1, Buffer.alloc(20), {expected: false})
  })

  it('should failed when token is unlock from wrong genesis', () => {
    simpleRouteUnlock(dummyTxId, 1, Buffer.alloc(20), {expected: false})
  })

  it('should failed when token is unlock from wrong checkContractInputIndex', () => {
    simpleRouteUnlock(dummyTxId, 1, Buffer.alloc(20), {expected: false, wrongCheckContractInputIndex: true})
  })

  it('it should succeed when unlock from contract', () => {
    const args = {
      tokenExpected: true,
      checkExpected: true,
    }
    for (let i = 1; i <= 2; i++) {
      for (let j = 1; j <= 3; j++) {
        unlockFromContract(i, j, 2, args)
      }
    }
  });

  it('it should failed when unlock from contract with wrong tokenInputIndex', () => {
    const args = {
      tokenExpected: [true, false],
      checkExpected: false,
      wrongNSenders: true,
    }
    unlockFromContract(2, 1, 1, args)
  });

  it('it should success when burn token', () => {
    const args = {
      tokenExpected: true,
      checkExpected: true,
      scriptHash: Buffer.alloc(20, 0)
    }
    unlockFromContract(2, 0, 1, args)
  });

  it('it should failed when not all token inputs is in burning address', () => {
    const args = {
      tokenExpected: [true, false],
      checkExpected: false,
      scriptHash: [Buffer.alloc(20, 0), Buffer.alloc(20, 1)]
    }
    unlockFromContract(2, 0, 1, args)
  });

  it('it should failed when try to take burning address token', () => {
    const [tokenSell, tokenSellTx] = createTokenSellContract(10000)
    const scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(tokenSell.lockingScript.toBuffer()))
    const args = {
      tokenExpected: [true, true],
      checkExpected: false,
      scriptHash: [Buffer.alloc(20, 0), scriptHash]
    }
    unlockFromContract(2, 1, 1, args)
  });

  it('it should failed when unlock from contract with wrong lockContractTx', () => {
    const args = {
      tokenExpected: false,
      checkExpected: true,
      wrongLockContractTx: true,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('it should failed when unlock from contract with wrong contract script hash', () => {
    const args = {
      tokenExpected: false,
      checkExpected: true,
      scriptHash: address2.hashBuffer,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('it should failed when unlock from contract with wrong rabinPubKey index', () => {
    const args = {
      tokenExpected: false,
      checkExpected: true,
      wrongRabinPubKeyIndex: true,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('it should failed when unlock from contract with wrong tokenID', () => {
    const args = {
      tokenExpected: false,
      checkExpected: false,
      wrongTokenID: true,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('it should failed when unlock from contract with wrong token code hash', () => {
    const args = {
      tokenExpected: false,
      checkExpected: false,
      wrongTokenCodeHash: true,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('it should failed when input token amount less then output token amount', () => {
    const args = {
      tokenExpected: true,
      checkExpected: false,
      outputTokenAdd: 100,
    }
    unlockFromContract(1, 1, 1, args)
  });

  it('should failed when fake many outputs into one output', () => {
    args = {
      tokenExpected: true,
      checkExpected: false,
    }
    unlockFromContractFake(args)
  }) 

});
