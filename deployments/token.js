const {
    bsv,
    buildContractClass,
    getPreimage,
    toHex,
    num2bin,
    SigHashPreimage,
    signTx,
    PubKey,
    Sig,
    Bytes,
    Ripemd160,
} = require('scryptlib');
const {
    DataLen,
    loadDesc,
    sendTx,
    showError,
} = require('../helper');
const {
    privateKey,
    privateKey2,
    privateKey3,
} = require('../privateKey');
const TokenProto = require('./TokenProto');
const {toBufferLE} = require('bigint-buffer')

const Rabin = require('../rabin/rabin')

const rabinPrivateKey = {
  "p": 5757440790098238249206056886132360783939976756626308615141839695681752813612764520921497694519841722889028334119917789649651692480869415368298368200263n,
  "q": 650047001204168007801848889418948532353073326909497585177081016045346562912146630794965372241635285465610094863279373295872825824127728241709483771067n
}
const rabinPubKey = Rabin.privKeyToPubKey(rabinPrivateKey.p, rabinPrivateKey.q)
const rabinPubKeyArray = [rabinPubKey, rabinPubKey, rabinPubKey]

const TokenUtil = require('./tokenUtil')
const utxo1 =  '757460adb1561ce3a7ba9ef4c9faf374456a850857c393d407a5f806ef7f353f'
const outIndex1 = 0
const bsvBalance1 = 10000000

const dustLimit = 546

const tokenName = Buffer.alloc(20, 0)
tokenName.write('test token name')
const tokenSymbol = Buffer.alloc(10, 0)
tokenSymbol.write('ttn')

const tokenValue = 1000000
const decimalNum = 8

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()

function createNewToken() {
  let outAmount1 = dustLimit + 10000
  let fee = 5000
  let genesisTx = TokenUtil.createGenesis(utxo1, outIndex1, bsv.Script.buildPublicKeyHashOut(address1), bsvBalance1, privateKey, fee, privateKey.publicKey, rabinPubKeyArray, tokenName, tokenSymbol, outAmount1, address1, decimalNum)

  let genesisScript = genesisTx.outputs[0].script
  let inputAmount = genesisTx.outputs[0].satoshis

  const rabinMsg = Buffer.alloc(1, 0)
  const rabinPaddingArray = [new Bytes('00'), new Bytes('00'), new Bytes('00')]
  const rabinSigArray = [0, 0, 0]
  fee = 10000
  const utxo2 = genesisTx.id
  const outIndex2 = genesisTx.outputs.length - 1
  const bsvBalance2 = genesisTx.outputs[outIndex2].satoshis
  const tokenTx = TokenUtil.createToken(genesisScript, tokenValue, address1, inputAmount, genesisTx.id, 0, dustLimit, privateKey, rabinPubKeyArray, decimalNum, utxo2, outIndex2, bsv.Script.buildPublicKeyHashOut(address1), bsvBalance2, privateKey, rabinMsg, rabinPaddingArray, rabinSigArray, address1, fee)

  //console.log('createTokenTx:', tokenTx.id, tokenTx.serialize())
  return {genesisTx, tokenTx}
}

// only one token input
function createTokenTransferTx(genesisTx, tokenTx, tokenOutIndex) {
  const tokenAmount1 = 1000
  const tokenAmount2 = 2000
  const tokenAmount3 = tokenValue - tokenAmount1 - tokenAmount2
  const inputAmount = tokenTx.outputs[tokenOutIndex].satoshis
  let fee = 10000

  const tokenInputArray = []
  const satoshiInputArray = []
  let checkRabinMsgArray = Buffer.alloc(0)
  let checkRabinPaddingArray = Buffer.alloc(0)
  let checkRabinSigArray = Buffer.alloc(0)
  const senderPrivKeyArray = []
  const satoshiInputPrivKeyArray = []
  const tokenOutputArray = []

  const tokenInput = {
    lockingScript: tokenTx.outputs[tokenOutIndex].script,
    satoshis: tokenTx.outputs[tokenOutIndex].satoshis,
    txId: tokenTx.id,
    outputIndex: tokenOutIndex
  }
  tokenInputArray.push(tokenInput)

  let tokenID
  let tokenCodeHash
  for (let i = 0; i < tokenInputArray.length; i++) {
    const tokenInput = tokenInputArray[i]
    const tokenScript = tokenInput.lockingScript
    inputTokenScript = tokenScript
    const tokenScriptBuf = tokenScript.toBuffer()
    const inputSatoshis = tokenInput.satoshis
    const txId = tokenInput.txId
    const outputIndex = tokenInput.outputIndex
    tokenID = TokenProto.getTokenID(tokenScriptBuf)
    tokenCodeHash = TokenProto.getContractCodeHash(tokenScriptBuf)

    const txidBuf = TokenUtil.getTxIdBuf(txId)
    const indexBuf = TokenUtil.getIndexBuf(outputIndex)
    const satoBuf = TokenUtil.getAmountBuf(inputSatoshis)
    const rabinMsg = Buffer.concat([
      txidBuf,
      indexBuf,
      satoBuf,
      TokenUtil.getScriptHashBuf(tokenScriptBuf)
    ])
    checkRabinMsgArray = Buffer.concat([checkRabinMsgArray, rabinMsg])

    for (let j = 0; j < 3; j++) {
      const rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
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
  }

  const tokenOutput = {
    address: address2,
    tokenAmount: tokenAmount1,
    satoshis: dustLimit
  }
  tokenOutputArray.push(tokenOutput)

  const tokenOutput2 = {
    address: address2,
    tokenAmount: tokenAmount2,
    satoshis: dustLimit
  }
  tokenOutputArray.push(tokenOutput2)

  const tokenOutput3 = {
    address: address2,
    tokenAmount: tokenAmount3,
    satoshis: dustLimit
  }
  tokenOutputArray.push(tokenOutput3)

  let outIndex = tokenTx.outputs.length - 1
  let bsvBalance = tokenTx.outputs[outIndex].satoshis
  let utxo = tokenTx.id

  const inputScript = bsv.Script.buildPublicKeyHashOut(address1)

  const scriptTx = TokenUtil.createRouteCheckTx(
    utxo, 
    outIndex,
    bsvBalance, 
    inputScript, 
    privateKey,
    address1,
    dustLimit, 
    fee, 
    tokenOutputArray, 
    rabinPubKeyArray,
    tokenID,
    tokenCodeHash)

  outIndex = scriptTx.outputs.length - 1
  bsvBalance = scriptTx.outputs[outIndex].satoshis
  utxo = scriptTx.id

  fee = 30000
  let changeSatoshi = inputAmount - fee - dustLimit * 3
  const changeAddress = address1
  const satoshiInput = {
    lockingScript: inputScript,
    satoshis: bsvBalance,
    txId: utxo,
    outputIndex: outIndex,
  }
  satoshiInputArray.push(satoshiInput)
  changeSatoshi += bsvBalance

  senderPrivKeyArray.push(privateKey)
  satoshiInputPrivKeyArray.push(privateKey)

  const tokenRabinMsg = Buffer.concat([
    TokenUtil.getTxIdBuf(genesisTx.id),
    TokenUtil.getIndexBuf(0),
    TokenUtil.getAmountBuf(genesisTx.outputs[0].satoshis),
    TokenUtil.getScriptHashBuf(genesisTx.outputs[0].script.toBuffer()),
    TokenUtil.getTxIdBuf(tokenTx.id)
  ])
  let rabinSigResult = Rabin.sign(tokenRabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
  let sig = rabinSigResult.signature
  let tokenRabinSigArray = [sig, sig, sig]
  let padding = new Bytes(Buffer.alloc(rabinSigResult.paddingByteCount, 0).toString('hex'))
  let tokenRabinPaddingArray = [padding, padding, padding]
  // the tokeTx prePrevTx is genesis Tx, so do not need address and amount
  let prevPrevTokenAddress = address1
  let prevPrevTokenAmount = 0

  const tx = TokenUtil.createTokenTransfer(
    scriptTx,
    tokenInputArray,
    satoshiInputArray,
    rabinPubKeyArray,
    checkRabinMsgArray,
    checkRabinPaddingArray,
    checkRabinSigArray,
    senderPrivKeyArray,
    satoshiInputPrivKeyArray,
    tokenOutputArray,
    changeSatoshi,
    changeAddress,
    tokenRabinMsg,
    tokenRabinPaddingArray,
    tokenRabinSigArray,
    prevPrevTokenAddress,
    prevPrevTokenAmount,
  )

  //console.log('createTokenTransferTx', tx.id, tx.serialize())
  const transferTx = tx
  return {scriptTx, transferTx}
}

(async() => {
  try {
    TokenUtil.initContractHash(rabinPubKeyArray)

    const {genesisTx, tokenTx} = createNewToken()

    //await sendTx(genesisTx)
    //await sendTx(tokenTx)
    console.log('genesisTx id:', genesisTx.id, genesisTx.serialize().length / 2)
    console.log('tokenTx id:', tokenTx.id, tokenTx.serialize().length / 2)

    // 1 input token with 3 output token
    const {scriptTx, transferTx} = createTokenTransferTx(genesisTx, tokenTx, 1)
    //await sendTx(scriptTx)
    //await sendTx(transferTx)

    console.log('checkScriptTx id:', scriptTx.id, scriptTx.serialize().length / 2)
    console.log('transferTx id:', transferTx.id, transferTx.serialize().length / 2)

  } catch (error) {
    console.log('Failed on testnet')
    showError(error)
  }
})()