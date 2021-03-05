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

const TokenProto = require('../../deployments/tokenProto')

// MSB of the sighash  due to lower S policy
const MSB_THRESHOLD = 0x7E
// make a copy since it will be mutated
let tx
const outputAmount = 222222

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
const Genesis = buildContractClass(compileContract('tokenGenesis.scrypt'))
const Token = buildContractClass(compileContract('token.scrypt'))
const address1 = privateKey.toAddress()
const tokenValue = 1000000
const buffValue = Buffer.alloc(8, 0)
buffValue.writeBigUInt64LE(BigInt(tokenValue))
const decimalNum = Buffer.from('08', 'hex')
const rabinPubKeyArray = [0, 0, 0]
const routeCheckCodeHash = Buffer.alloc(20, 0).toString('hex')
const unlockContractCodeHash = routeCheckCodeHash
const genesisHash = routeCheckCodeHash
const tokenID = Buffer.concat([
  Buffer.from(dummyTxId, 'hex').reverse(),
  Buffer.alloc(4, 0),
])

let genesis, result, genesisScript

function createToken(oracleData) {
  const token = new Token(rabinPubKeyArray, new Bytes(routeCheckCodeHash), new Bytes(unlockContractCodeHash), new Bytes(genesisHash))
  token.setDataPart(oracleData.toString('hex'))
  const lockingScript = token.lockingScript
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputAmount
  }))

  const inIndex = 0
  const inputAmount = inputSatoshis

  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  let preimage
  // preimage optimize
  for (let i = 0; ; i++) {
    tx.nLockTime = i
    const preimage_ = getPreimage(tx, genesisScript.toASM(), inputAmount, inputIndex=inIndex, sighashType=sigtype)
    const preimageHex = toHex(preimage_)
    const h = bsv.crypto.Hash.sha256sha256(Buffer.from(preimageHex, 'hex'))
    const msb = h.readUInt8()
    if (msb < MSB_THRESHOLD) {
        // the resulting MSB of sighash must be less than the threshold
        preimage = preimage_
        break
    }
  }
  const sig = signTx(tx, privateKey, genesisScript.toASM(), inputAmount, inputIndex=inIndex, sighashType=sigtype)

  const txContext = { 
    tx: tx, 
    inputIndex: inIndex, 
    inputSatoshis: inputAmount
  }

  result = genesis.unlock(
    new SigHashPreimage(toHex(preimage)), 
    new Sig(toHex(sig)), 
    0,
    new Bytes(lockingScript.toHex()), 
    outputAmount,
    new Ripemd160(address1.hashBuffer.toString('hex')),
    0,
    ).verify(txContext)
  return result
}

describe('Test genesis contract unlock In Javascript', () => {

  beforeEach(() => {
    const token = new Token(rabinPubKeyArray, new Bytes(routeCheckCodeHash), new Bytes(unlockContractCodeHash), new Bytes(genesisHash))
    token.setDataPart(Buffer.alloc(TokenProto.getHeaderLen(), 0).toString('hex'))
    const lockingScript = token.lockingScript.toBuffer()
    genesis = new Genesis(new PubKey(toHex(issuerPubKey)))
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

  it('should succeed', () => {
    const oracleData = Buffer.concat([
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
    const result = createToken(oracleData)
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