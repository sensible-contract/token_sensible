const { expect, util } = require('chai');
const {
  bsv,
  buildContractClass,
  getPreimage,
  toHex,
  SigHashPreimage,
  Bytes,
} = require('scryptlib');

const {
  loadDesc,
  inputSatoshis,
  dummyTxId,
  compileContract,
} = require('../../helper');

const{
  privKeyToPubKey,
  sign,
  } = require("../../rabin/rabin");

const TokenProto = require('../../deployments/tokenProto')
const TokenUtil = require('../../deployments/tokenUtil')
const Common = require('../../deployments/common')
const toBufferLE = Common.toBufferLE

const utils = module.exports

utils.rabinPrivateKey = Common.rabinPrivateKey
utils.rabinPubKey = privKeyToPubKey(utils.rabinPrivateKey.p, utils.rabinPrivateKey.q)

utils.oracleNum = Common.oracleNum
utils.oracleVerifyNum = Common.oracleVerifyNum
utils.rabinPubKeyArray = Common.rabinPubKeyArray
utils.rabinPubKeyIndexArray = Common.rabinPubKeyIndexArray

utils.genContract = Common.genContract

utils.addInput = function(tx, lockingScript, outputIndex, prevouts, prevTxId=null, satoshis=null) {
  if (prevTxId === null) {
    prevTxId = dummyTxId
  }
  if (satoshis === null) {
    satoshis = inputSatoshis
  }
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: prevTxId,
    outputIndex: outputIndex,
    script: ''
  }), lockingScript, satoshis)
  prevouts.push(TokenUtil.getTxIdBuf(prevTxId))
  prevouts.push(TokenUtil.getUInt32Buf(outputIndex))
}

utils.addOutput = function(tx, lockingScript, outputSatoshis=inputSatoshis) {
  if (typeof outputSatoshis === 'bigint') {
    outputSatoshis = Number(outputSatoshis)
  }
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputSatoshis
  }))
  //console.log('addOutput: output:', tx.outputs.length, tx.outputs[tx.outputs.length-1].toBufferWriter().toBuffer().toString('hex'))
}

utils.createRabinMsg = function(txid, outputIndex, satoshis, scriptBuf, spendByTxId=null) {
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
  let rabinSignResult = sign(rabinMsg.toString('hex'), utils.rabinPrivateKey.p, utils.rabinPrivateKey.q, utils.rabinPubKey)
  const rabinSign = rabinSignResult.signature
  const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
  let rabinPaddingArray = []
  let rabinSigArray = []
  for (let i = 0; i < utils.oracleVerifyNum; i++) {
    rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
    rabinSigArray.push(rabinSign)
  }
  return [rabinMsg, rabinPaddingArray, rabinSigArray]
}

utils.verifyTokenUnlockContractCheck = function(tx, unlockContractCheck, inputIndex, prevouts, inputTokenIndexes, tokenOutputIndexes, expected=true) {

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, unlockContractCheck.lockingScript.toASM(), inputSatoshis, inputIndex=inputIndex, sighashType=sigtype)
  const txContext =  {
    tx: tx,
    inputIndex: inputIndex,
    inputSatoshis: inputSatoshis
  }

  let inputRabinMsgArray = Buffer.alloc(0)
  let inputRabinPaddingArray = Buffer.alloc(0)
  let inputRabinSignArray = Buffer.alloc(0)
  let inputTokenAddressArray = Buffer.alloc(0)
  let inputTokenAmountArray = Buffer.alloc(0)
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

    const rabinSignResult = sign(msg.toString('hex'), utils.rabinPrivateKey.p, utils.rabinPrivateKey.q, utils.rabinPubKey)
    let padding = Buffer.concat([
      TokenUtil.getUInt16Buf(rabinSignResult.paddingByteCount),
      Buffer.alloc(rabinSignResult.paddingByteCount)
    ])
    for (let i = 0; i < utils.oracleVerifyNum; i++) {
      inputRabinPaddingArray = Buffer.concat([
        inputRabinPaddingArray,
        padding
      ])
    }
    const sigBuf = toBufferLE(rabinSignResult.signature, TokenUtil.RABIN_SIG_LEN)
    for (let i = 0; i < utils.oracleVerifyNum; i++) {
      inputRabinSignArray = Buffer.concat([
        inputRabinSignArray,
        sigBuf
      ])
    }
  }

  let otherOutputArray = Buffer.alloc(0)
  let tokenOutputSatoshiArray = Buffer.alloc(0)
  let tokenOutputIndexArray = Buffer.alloc(0)
  let j = 0;
  const nOutputs = tx.outputs.length
  for (let i = 0; i < nOutputs; i++) {
    const tokenOutIndex = tokenOutputIndexes[j]
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
      const output = tx.outputs[i].toBufferWriter().toBuffer()
      otherOutputArray = Buffer.concat([
        otherOutputArray,
        TokenUtil.getUInt32Buf(output.length),
        output
      ])
    }
  }

  const result = unlockContractCheck.unlock(
    new SigHashPreimage(toHex(preimage)),
    new Bytes(tokenScript.toBuffer().toString('hex')),
    new Bytes(prevouts.toString('hex')),
    new Bytes(inputRabinMsgArray.toString('hex')),
    new Bytes(inputRabinPaddingArray.toString('hex')),
    new Bytes(inputRabinSignArray.toString('hex')),
    utils.rabinPubKeyIndexArray,
    new Bytes(inputTokenAddressArray.toString('hex')),
    new Bytes(inputTokenAmountArray.toString('hex')),
    nOutputs,
    new Bytes(tokenOutputIndexArray.toString('hex')),
    new Bytes(tokenOutputSatoshiArray.toString('hex')),
    new Bytes(otherOutputArray.toString('hex'))
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
}