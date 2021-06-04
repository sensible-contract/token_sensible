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
const { rabinPubKeyArray, rabinPubKeyIndexArray } = require('./utils');

let tx
const outputAmount = inputSatoshis

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
const Genesis = buildContractClass(compileContract('tokenGenesis.scrypt'))
const Token = buildContractClass(compileContract('token.scrypt'))
const address1 = privateKey.toAddress()
const tokenValue = 1000000
const buffValue = Buffer.alloc(8, 0)
buffValue.writeBigUInt64LE(BigInt(tokenValue))
const decimalNum = Buffer.from('08', 'hex')
const routeCheckCodeHash = new Bytes(Buffer.alloc(20, 0).toString('hex'))
const routeCheckCodeHashArray = [routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash, routeCheckCodeHash]
const unlockContractCodeHash = routeCheckCodeHash
const unlockContractCodeHashArray = routeCheckCodeHashArray
let genesisHash
const tokenID = Buffer.concat([
  Buffer.from(dummyTxId, 'hex').reverse(),
  Buffer.alloc(4, 0),
])

let genesis, result, genesisScript

function createToken(oracleData) {
  // add genesis output
  const scriptBuf = genesisScript.toBuffer()
  const newScriptBuf = TokenProto.getNewGenesisScript(scriptBuf, tokenID)
  genesisHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(newScriptBuf)).toString('hex')
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.fromBuffer(newScriptBuf),
    satoshis: outputAmount
  }))

  const token = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash))
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
    outputAmount,
    new Bytes(lockingScript.toHex()), 
    outputAmount,
    new Ripemd160(address1.hashBuffer.toString('hex')),
    0,
    new Bytes('')
    ).verify(txContext)
  return result
}

describe('Test genesis contract unlock In Javascript', () => {

  beforeEach(() => {
    genesis = new Genesis(new PubKey(toHex(issuerPubKey)), rabinPubKeyArray)
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      Buffer.alloc(20, 0), // address
      Buffer.alloc(8, 0), // token value
      Buffer.alloc(36, 0), // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    genesis.setDataPart(oracleData.toString('hex'))

    genesisScript = genesis.lockingScript

    tx = new bsv.Transaction()
    tx.addInput(new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ''
      }), bsv.Script.fromASM(genesisScript.toASM()), inputSatoshis)

  });

  it('should succeed when issue token', () => {
    let oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer,
      buffValue,
      tokenID,
      tokenType, // type
      PROTO_FLAG
    ])
    let result = createToken(oracleData)
    expect(result.success, result.error).to.be.true

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

    const token = new Token(rabinPubKeyArray, routeCheckCodeHashArray, unlockContractCodeHashArray, new Bytes(genesisHash))
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

    /*const satoshiBuf = Buffer.alloc(8, 0)
    satoshiBuf.writeBigUInt64LE(BigInt(inputAmount))
    const scriptHash = Buffer.from(bsv.crypto.Hash.sha256ripemd160(genesisScript.toBuffer()))
    let rabinMsg = Buffer.concat([
      tokenID,
      satoshiBuf,
      scriptHash,
      Buffer.from([...Buffer.from(prevTx.id, 'hex')].reverse()),
    ])
    const rabinSignResult = sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
    //console.log('rabinsignature:', msg.toString('hex'), rabinSignResult.paddingByteCount, rabinSignResult.signature)
    const rabinSign = rabinSignResult.signature
    const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
    let rabinPaddingArray = []
    let rabinSigArray = []
    for (let i = 0; i < 2; i++) {
      rabinPaddingArray.push(new Bytes(rabinPadding.toString('hex')))
      rabinSigArray.push(rabinSign)
    }*/
    const [rabinMsg, rabinPaddingArray, rabinSigArray] = Utils.createRabinMsg(dummyTxId, 0, inputAmount, genesisScript.toBuffer(), prevTx.id)

    const genesis = new Genesis(new PubKey(toHex(issuerPubKey)), rabinPubKeyArray)
    oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      Buffer.alloc(20, 0), // address
      Buffer.alloc(8, 0), // token value
      tokenID,
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
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    let result = createToken(oracleData)
    expect(result.success, result.error).to.be.false

    const oracleData2 = Buffer.concat([
      tokenName.subarray(0, tokenName.length - 2),
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    result = createToken(oracleData2)
    expect(result.success, result.error).to.be.false
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
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    let result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  })

  it('should failed when get wrong tokenSymbol', () => {
    const oracleData = Buffer.concat([
      tokenName,
      Buffer.alloc(tokenSymbol.length, 0),
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    let result = createToken(oracleData)
    expect(result.success, result.error).to.be.false

    // wrong token symbol length
    const oracleData2 = Buffer.concat([
      tokenName,
      tokenSymbol.subarray(0, tokenSymbol.length - 2),
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    result = createToken(oracleData2)
    expect(result.success, result.error).to.be.false
  });

  it('should failed when get wrong genesis flag', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      genesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    const result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  });

  it('should failed when get wrong tokenID', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      Buffer.alloc(tokenID.length, 0), // script code hash
      tokenType, // type
      PROTO_FLAG
    ])
    const result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  });
  it('should failed when get wrong tokenType', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      Buffer.alloc(tokenType.length, 0), // type
      PROTO_FLAG
    ])
    const result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  });
  it('should failed when get wrong proto flag', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      decimalNum,
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    const result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  });
  it('should failed when get wrong decimalNum', () => {
    const oracleData = Buffer.concat([
      tokenName,
      tokenSymbol,
      nonGenesisFlag, 
      Buffer.from('01', 'hex'),
      address1.hashBuffer, // address
      buffValue, // token value
      tokenID, // script code hash
      tokenType, // type
      Buffer.alloc(PROTO_FLAG.length, 0)
    ])
    const result = createToken(oracleData)
    expect(result.success, result.error).to.be.false
  });
});