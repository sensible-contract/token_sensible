
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
  compileContract,
} = require('../helper');
const Rabin = require('../rabin/rabin')

const common = module.exports

common.rabinPrivateKey = {
  "p": 5757440790098238249206056886132360783939976756626308615141839695681752813612764520921497694519841722889028334119917789649651692480869415368298368200263n,
  "q": 650047001204168007801848889418948532353073326909497585177081016045346562912146630794965372241635285465610094863279373295872825824127728241709483771067n
}
common.rabinPubKey = Rabin.privKeyToPubKey(common.rabinPrivateKey.p, common.rabinPrivateKey.q)
common.rabinPubKeyArray = [common.rabinPubKey, common.rabinPubKey, common.rabinPubKey]
common.rabinPubKeyIndexArray = [0, 1]

common.genContract = function(name, use_desc=true) {
  if (use_desc) {
  return buildContractClass(loadDesc(name + '_desc.json'))
  }
  else {
  return buildContractClass(compileContract(name + '.scrypt'))
  }
}

common.getUInt8Buf = function(amount) {
  const buf = Buffer.alloc(1, 0)
  buf.writeUInt8(amount)
  return buf

}

common.getUInt16Buf = function(amount) {
  const buf = Buffer.alloc(2, 0)
  buf.writeUInt16LE(amount)
  return buf
}

common.getUInt32Buf = function(index) {
  const buf = Buffer.alloc(4, 0)
  buf.writeUInt32LE(index)
  return buf
}

common.getUInt64Buf = function(amount) {
  const buf = Buffer.alloc(8, 0)
  buf.writeBigUInt64LE(BigInt(amount))
  return buf
}

common.getTxIdBuf = function(txid) {
  const buf = Buffer.from(txid, 'hex').reverse()
  return buf
}

common.getScriptHashBuf = function(scriptBuf) {
  const buf = Buffer.from(bsv.crypto.Hash.sha256ripemd160(scriptBuf))
  return buf
}

common.writeVarint = function(buf) {

		const n = buf.length;

    let res = Buffer.alloc(0)
		if (n < 0xfd) {
			header = common.getUInt8Buf(n);
		} else if (n < 0x10000) {
			header = Buffer.concat([Buffer.from('fd', 'hex') , common.getUInt16Buf(n)]);
		} else if (n < 0x100000000) {
			header = Buffer.concat([Buffer.from('fe', 'hex'), common.getUInt32Buf(n)]);
		} else if (n < 0x10000000000000000) {
			header = Buffer.concat([Buffer.from('ff', 'hex'), common.getUInt64Buf(n)]);
		}

		return Buffer.concat([header, buf]);
}

common.buildOutput = function(outputScriptBuf, outputSatoshis) {
  return Buffer.concat([
    common.getUInt64Buf(outputSatoshis),
    common.writeVarint(outputScriptBuf)
  ])
}

common.addInput = function(tx, prevTxId, prevTxOutputIndex, lockingScript, utxoSatoshis, prevouts, p2pkh=false) {
  if (p2pkh === true) {
    tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
      output: new bsv.Transaction.Output({
        script: lockingScript,
        satoshis: utxoSatoshis,
      }),
      prevTxId: prevTxId,
      outputIndex: prevTxOutputIndex,
      script: bsv.Script.empty()
    }))
  } else {
    tx.addInput(new bsv.Transaction.Input({
      prevTxId: prevTxId,
      outputIndex: prevTxOutputIndex,
      script: ''
    }), lockingScript, utxoSatoshis)
  }
  prevouts.push(common.getTxIdBuf(prevTxId))
  prevouts.push(common.getUInt32Buf(prevTxOutputIndex))
}

common.addOutput = function(tx, lockingScript, outputSatoshis) {
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputSatoshis
  }))
  //console.log('addOutput: output:', tx.outputs.length, tx.outputs[tx.outputs.length-1].toBufferWriter().toBuffer().toString('hex'))
}

common.createRabinMsg = function(txid, outputIndex, satoshis, scriptBuf, spendByTxId=null) {
  const scriptHash = bsv.crypto.Hash.sha256ripemd160(scriptBuf)
  let rabinMsg = Buffer.concat([
    common.getTxIdBuf(txid),
    common.getUInt32Buf(outputIndex),
    common.getUInt64Buf(satoshis),
    scriptHash
  ])
  if (spendByTxId !== null) {
    rabinMsg = Buffer.concat([rabinMsg, common.getTxIdBuf(spendByTxId)])
  }
  let rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), common.rabinPrivateKey.p, common.rabinPrivateKey.q, common.rabinPubKey)
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

common.createScriptTx = function(bsvFeeTx, bsvFeeOutputIndex, lockingScript, outputSatoshis, fee, changeAddress, inputPrivKey) {
  const output = bsvFeeTx.outputs[bsvFeeOutputIndex]
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
    output: new bsv.Transaction.Output({
      script: output.script,
      satoshis: output.satoshis
    }),
    prevTxId: bsvFeeTx.id,
    outputIndex: bsvFeeOutputIndex,
    script: bsv.Script.empty()
  }))
  const changeAmount = output.satoshis - fee - outputSatoshis 
  tx.addOutput(new bsv.Transaction.Output({
    script: lockingScript,
    satoshis: outputSatoshis,
  }))
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(changeAddress),
    satoshis: changeAmount,
  }))

  // sign
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const hashData = bsv.crypto.Hash.sha256ripemd160(inputPrivKey.publicKey.toBuffer())
  const sig = tx.inputs[0].getSignatures(tx, inputPrivKey, 0, sigtype, hashData)
  tx.inputs[0].addSignature(tx, sig[0])

  return tx
}

common.signP2PKH = function(tx, privKey, inputIndex) {
  const sigtype = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const hashData = bsv.crypto.Hash.sha256ripemd160(privKey.publicKey.toBuffer())
  const sig = tx.inputs[inputIndex].getSignatures(tx, privKey, inputIndex, sigtype, hashData)
  tx.inputs[inputIndex].addSignature(tx, sig[0])
}