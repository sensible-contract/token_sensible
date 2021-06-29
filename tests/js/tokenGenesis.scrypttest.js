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
  Ripemd160
} = require('scryptlib');
const {
  loadDesc,
  inputSatoshis,
  dummyTxId,
  compileContract
} = require('../../helper');

const {
    privateKey,
} = require('../../privateKey');

const{ generatePrivKey,
  privKeyToPubKey,
  sign,
  verify } = require("../../rabin/rabin");

const Proto = require('../../deployments/protoheader')
const TokenProto = require('../../deployments/tokenProto')
const Utils = require('./utils');
const { rabinPubKeyVerifyArray, rabinPubKeyIndexArray, rabinPubKeyHashArray, rabinPubKeyHashArrayHash } = require('../../deployments/common');

let tx
const outputAmount = inputSatoshis
const genContract = Utils.genContract

let Token, Genesis, TransferCheck, UnlockContractCheck
function initContract() {
  const use_desc = false
  const use_release = false
  Genesis = genContract('tokenGenesis', use_desc, use_release)
  Token = genContract('token', use_desc, use_release)
  TransferCheck = genContract('tokenTransferCheck', use_desc, use_release)
  UnlockContractCheck = genContract('tokenUnlockContractCheck', use_desc, use_release)
}
initContract()

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
const tokenValue = 1000000
const buffValue = Buffer.alloc(8, 0)
buffValue.writeBigUInt64LE(BigInt(tokenValue))
const decimalNum = Buffer.from('08', 'hex')
const rtransferCheckCodeHash = new Bytes(Buffer.alloc(20, 0).toString('hex'))
const rtransferCheckCodeHashArray = [rtransferCheckCodeHash, rtransferCheckCodeHash, rtransferCheckCodeHash, rtransferCheckCodeHash, rtransferCheckCodeHash]
const unlockContractCodeHashArray = rtransferCheckCodeHashArray
const sensibleID = Buffer.concat([
  Buffer.from(dummyTxId, 'hex').reverse(),
  Buffer.alloc(4, 0),
])

let genesis, result, genesisScript, genesisHash

function createToken(oracleData, options={}) {
  const scriptBuf = genesisScript.toBuffer()
  const newScriptBuf = TokenProto.getNewGenesisScript(scriptBuf, sensibleID)
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.fromBuffer(newScriptBuf),
    satoshis: outputAmount
  }))

  const token = new Token(rtransferCheckCodeHashArray, unlockContractCodeHashArray)
  token.setDataPart(oracleData.toString('hex'))
  const lockingScript = token.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputAmount
  }))

  const inIndex = 0
  const inputAmount = inputSatoshis

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const preimage = getPreimage(tx, genesisScript.toASM(), inputAmount, inputIndex=inIndex, sighashType=sigtype)
  const sig = signTx(tx, privateKey, genesisScript.toASM(), inputAmount, inputIndex=inIndex, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: inIndex, 
    inputSatoshis: inputAmount
  }

  const [rabinMsg, rabinPaddingArray, rabinSigArray] = Utils.createRabinMsg(dummyTxId, 0, inputAmount, genesisScript.toBuffer(), dummyTxId)

  result = genesis.unlock(
    new SigHashPreimage(toHex(preimage)), 
    new Sig(toHex(sig)), 
    new Bytes(rabinMsg.toString('hex')),
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    new Bytes(rabinPubKeyHashArray.toString('hex')),
    outputAmount,
    new Bytes(lockingScript.toHex()), 
    outputAmount,
    new Ripemd160(address1.hashBuffer.toString('hex')),
    0,
    new Bytes('')
    ).verify(txContext)
  if (options.expected === false) {
    expect(result.success, result.error).to.be.false
  } else {
    expect(result.success, result.error).to.be.true
  }

  return token
}

describe('Test genesis contract unlock In Javascript', () => {

  beforeEach(() => {
    genesis = new Genesis(new PubKey(toHex(issuerPubKey)))
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      Buffer.alloc(20, 0), // address
      Buffer.alloc(8, 0), // token value
      Buffer.alloc(20, 0), // genesisHash
      rabinPubKeyHashArrayHash,
      Buffer.alloc(36, 0), // sensibleID
      tokenType, // type
      PROTO_FLAG
    ])
    genesis.setDataPart(oracleData.toString('hex'))

    genesisScript = genesis.lockingScript
    const scriptBuf = genesisScript.toBuffer()
    const newScriptBuf = TokenProto.getNewGenesisScript(scriptBuf, sensibleID)
    genesisHash = bsv.crypto.Hash.sha256ripemd160(newScriptBuf)

    tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ''
      }), bsv.Script.fromASM(genesisScript.toASM()), inputSatoshis)

  });

  it('should succeed when issue token', () => {

    // add genesis output
    let oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer,
      buffValue,
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID,
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData)
    // issue token again
    const prevTx = tx
    tx =  new bsv.Transaction()
    const newGenesisScript = prevTx.outputs[0].script
    tx.addInput(bsv.Transaction.Input({
      prevTxId: prevTx.id,
      outputIndex: 0,
      script: ''
    }), newGenesisScript, outputAmount)

    tx.addOutput(new bsv.Transaction.Output({
      script: newGenesisScript,
      satoshis: outputAmount
    }))

    const token = new Token(rtransferCheckCodeHashArray, unlockContractCodeHashArray)
    token.setDataPart(oracleData.toString('hex'))
    const lockingScript = token.lockingScript
    tx.addOutput(new bsv.Transaction.Output({
      script: lockingScript,
      satoshis: outputAmount
    }))

    const inIndex = 0
    const inputAmount = inputSatoshis

    const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
    const preimage = getPreimage(tx, newGenesisScript.toASM(), outputAmount, inputIndex=inIndex, sighashType=sigtype)
    const sig = signTx(tx, privateKey, newGenesisScript.toASM(), outputAmount, inputIndex=inIndex, sighashType=sigtype)

    const txContext = { 
      tx: tx, 
      inputIndex: inIndex, 
      inputSatoshis: outputAmount
    }

    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Utils.createRabinMsg(dummyTxId, 0, inputAmount, genesisScript.toBuffer(), prevTx.id)

    const genesis = new Genesis(new PubKey(toHex(issuerPubKey)))
    oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      Buffer.alloc(20, 0), // address
      Buffer.alloc(8, 0), // token value
      Buffer.alloc(20, 0), // genesisHash
      rabinPubKeyHashArrayHash,
      sensibleID,
      tokenType, // type
      PROTO_FLAG
    ])
    genesis.setDataPart(oracleData.toString('hex'))
    result = genesis.unlock(
      new SigHashPreimage(toHex(preimage)), 
      new Sig(toHex(sig)), 
      new Bytes(rabinMsg.toString('hex')),
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      new Bytes(rabinPubKeyHashArray.toString('hex')),
      outputAmount,
      new Bytes(lockingScript.toHex()), 
      outputAmount,
      new Ripemd160(address1.hashBuffer.toString('hex')),
      0,
      new Bytes('')
      ).verify(txContext)
    expect(result.success, result.error).to.be.true
  });

  it('should failed when get wrong tokenName', () => {
    const oracleData = Buffer.concat([
      Buffer.alloc(tokenName.length, 0),
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})

    const oracleData2 = Buffer.concat([
      tokenName.subarray(0, tokenName.length - 2),
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData2, {expected: false})
  });
  it('should failed when add wrong data length', () => {
    const oracleData = Buffer.concat([
      Buffer.alloc(0),
      tokenName,
      Buffer.alloc(tokenSymbol.length, 0),
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})
  })

  it('should failed when get wrong tokenSymbol', () => {
    const oracleData = Buffer.concat([
      tokenName,
      Buffer.alloc(tokenSymbol.length, 0),
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})

    // wrong token symbol length
    const oracleData2 = Buffer.concat([
      tokenName,
      tokenSymbol.subarray(0, tokenSymbol.length - 2),
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData2, {expected: false})
  });

  it('should failed when get wrong genesis flag', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})
  });

  it('should failed when get wrong tokenID', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      Buffer.alloc(sensibleID.length, 0), // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})
  });
  it('should failed when get wrong tokenType', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      Buffer.alloc(tokenType.length, 0), // type
      PROTO_FLAG
    ])
    createToken(oracleData, {expected: false})
  });
  it('should failed when get wrong proto flag', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    createToken(oracleData, {expected: false})
  });
  it('should failed when get wrong decimalNum', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      Buffer.from('01', 'hex'),
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    createToken(oracleData, {expected: false})
  });
  it('should failed when get wrong genesisHash', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      Buffer.from('01', 'hex'),
      address1.hashBuffer, // address
      buffValue, // token value
      Buffer.alloc(20, 0),
      rabinPubKeyHashArrayHash,
      sensibleID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    createToken(oracleData, {expected: false})
  });
  it('should failed when get wrong rabinPubKeyHashArrayHash', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      Buffer.from('01', 'hex'),
      address1.hashBuffer, // address
      buffValue, // token value
      genesisHash,
      Buffer.alloc(20, 0),
      sensibleID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    createToken(oracleData, {expected: false})
  });
});