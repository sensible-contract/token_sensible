const { expect } = require('chai');
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

const {toBufferLE} = require('bigint-buffer')

const TokenProto = require('../../deployments/tokenProto')
const TokenUtil = require('../../deployments/tokenUtil')

const utils = module.exports

utils.rabinPrivateKey = {
  "p": 5757440790098238249206056886132360783939976756626308615141839695681752813612764520921497694519841722889028334119917789649651692480869415368298368200263n,
  "q": 650047001204168007801848889418948532353073326909497585177081016045346562912146630794965372241635285465610094863279373295872825824127728241709483771067n
}
utils.rabinPubKey = privKeyToPubKey(utils.rabinPrivateKey.p, utils.rabinPrivateKey.q)

utils.genContract = function(name, use_desc=false) {
  if (use_desc) {
    return buildContractClass(loadDesc(name + '_desc.json'))
  }
  else {
    return buildContractClass(compileContract(name + '.scrypt'))
  }
}

utils.addInput = function(tx, lockingScript, i, prevouts, prevTxId=null) {
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

utils.addOutput = function(tx, lockingScript, outputSatoshis=inputSatoshis) {
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputSatoshis
  }))
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
  for (let i = 0; i < 2; i++) {
    rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
    rabinSigArray.push(rabinSign)
  }
  return [rabinMsg, rabinPaddingArray, rabinSigArray]
}

utils.verifyTokenUnlockContractCheck = function(tx, unlockContractCheck, inputIndex, nTokenInputs, prevouts, inputTokenIndexes, tokenOutputIndexes, isBurn=false, expected=true) {

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

    const rabinSignResult = sign(msg.toString('hex'), utils.rabinPrivateKey.p, utils.rabinPrivateKey.q, utils.rabinPubKey)
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
    nTokenInputs,
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
    isBurn
  ).verify(txContext)
  if (expected === true) {
    expect(result.success, result.error).to.be.true
  } else {
    expect(result.success, result.error).to.be.false
  }
}