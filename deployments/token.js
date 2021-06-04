const {
  bsv,
  Bytes,
} = require('scryptlib');
const {
  sendTx,
  showError,
} = require('../helper');
const {
  privateKey,
  privateKey2,
} = require('../privateKey');
const TokenProto = require('./TokenProto');

const Common = require('./common')
const TokenUtil = require('./tokenUtil')

const utxo1 =  'd4643990952233445403f5ec050e96f491702fb60cb9b704009d50358e589f69'
const outIndex1 = 3
const bsvBalance1 = 9927270

const dustLimit = 546

const tokenName = Buffer.alloc(20, 0)
tokenName.write('test token name')
const tokenSymbol = Buffer.alloc(10, 0)
tokenSymbol.write('ttn')

const tokenValue = 1000000
const decimalNum = 8

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()

async function sendTestTx(tx) {
  const res = await sendTx(tx) 
  console.log("sendTx res:", res)
}

function createNewToken() {
  let outAmount1 = dustLimit + 10000
  let fee = 5000
  let genesisTx = TokenUtil.createGenesis(utxo1, outIndex1, bsv.Script.buildPublicKeyHashOut(address1), bsvBalance1, privateKey, fee, privateKey.publicKey, Common.rabinPubKeyArray, tokenName, tokenSymbol, outAmount1, address1, decimalNum)

  let genesisScript = genesisTx.outputs[0].script
  let inputAmount = genesisTx.outputs[0].satoshis

  const rabinMsg = Buffer.alloc(1, 0)
  const rabinPaddingArray = Array(Common.oracleVerifyNum).fill(new Bytes(''))
  const rabinSigArray = Array(Common.oracleVerifyNum).fill(0)
  fee = 10000
  const utxo2 = genesisTx.id
  const outIndex2 = genesisTx.outputs.length - 1
  const bsvBalance2 = genesisTx.outputs[outIndex2].satoshis
  const [tokenContract, tokenTx] = TokenUtil.createToken(genesisScript, tokenValue, address1, inputAmount, genesisTx.id, 0, dustLimit, privateKey, Common.rabinPubKeyArray, decimalNum, utxo2, outIndex2, bsv.Script.buildPublicKeyHashOut(address1), bsvBalance2, privateKey, rabinMsg, rabinPaddingArray, rabinSigArray, address1, fee)

  //console.log('createTokenTx:', tokenTx.id, tokenTx.serialize())
  return [genesisTx, tokenContract, tokenTx]
}

// only one token input
function createTokenTransferTx(genesisTx, tokenTx, tokenOutIndex, tokenContract) {
  let fee = 10000

  const tokenInputArray = []
  const satoshiInputArray = []
  const senderPrivKeyArray = []
  const satoshiInputPrivKeyArray = []
  const tokenOutputArray = []

  const tokenScriptBuf = tokenTx.outputs[tokenOutIndex].script.toBuffer()
  const tokenID = TokenProto.getTokenID(tokenScriptBuf)
  const tokenCodeHash = TokenProto.getContractCodeHash(tokenScriptBuf)
  const tokenInput = {
    lockingScript: tokenTx.outputs[tokenOutIndex].script,
    satoshis: tokenTx.outputs[tokenOutIndex].satoshis,
    txId: tokenTx.id,
    outputIndex: tokenOutIndex,
    prevTokenTx: genesisTx,
    prevTokenOutputIndex: 0,
    tokenContract: tokenContract
  }
  tokenInputArray.push(tokenInput)

  const nTokenOutputs = 3
  for (let i = 0; i < nTokenOutputs; i++) {
    let tokenAmount = 10000
    if (i == nTokenOutputs - 1) {
      tokenAmount = tokenValue - 10000 * (nTokenOutputs - 1)
    }
    const tokenOutput = {
      address: address1.hashBuffer,
      tokenAmount: tokenAmount,
      satoshis: dustLimit
    }
    tokenOutputArray.push(tokenOutput)
    senderPrivKeyArray.push(privateKey)
  }

  let bsvFeeTx = tokenTx
  let bsvFeeOutputIndex = tokenTx.outputs.length - 1
  const [routeCheck, routeCheckTx] = TokenUtil.createRouteCheckTx(bsvFeeTx, bsvFeeOutputIndex, privateKey, dustLimit, fee, address1, 1, tokenOutputArray, tokenID, tokenCodeHash)

  fee = 30000
  const changeAddress = address1
  const satoshiInput = {
    tx: routeCheckTx,
    outputIndex: 1
  }
  satoshiInputArray.push(satoshiInput)
  satoshiInputPrivKeyArray.push(privateKey)

  const tx = TokenUtil.createTokenTransfer(
    routeCheckTx,
    routeCheck,
    tokenInputArray,
    satoshiInputArray,
    Common.rabinPubKeyArray,
    senderPrivKeyArray,
    satoshiInputPrivKeyArray,
    tokenOutputArray,
    fee,
    changeAddress
  )

  //console.log('createTokenTransferTx', tx.id, tx.serialize())
  const transferTx = tx
  return [routeCheckTx, transferTx]
}

(async() => {
  try {
    TokenUtil.initContractHash(Common.rabinPubKeyArray)

    const [genesisTx, tokenContract, tokenTx] = createNewToken()

    console.log('genesisTx id:', genesisTx.id, genesisTx.serialize().length / 2)
    console.log('tokenTx id:', tokenTx.id, tokenTx.serialize().length / 2)

    // 1 input token with 3 output token
    const [scriptTx, transferTx] = createTokenTransferTx(genesisTx, tokenTx, 1, tokenContract)

    console.log('checkScriptTx id:', scriptTx.id, scriptTx.serialize().length / 2)
    console.log('transferTx id:', transferTx.id, transferTx.serialize().length / 2)

    const sendFlag = false
    if (sendFlag) {
      await sendTestTx(genesisTx)
      await sendTestTx(tokenTx)
      await sendTestTx(scriptTx)
      await sendTestTx(transferTx)
    }
  } catch (error) {
    console.log('Failed on testnet')
    showError(error)
  }
})()