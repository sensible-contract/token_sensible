
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
  readFileSync,
  existsSync
} = require('fs')
const path = require('path')

const {
  loadDesc,
  compileContract,
} = require('../helper');
const Rabin = require('../rabin/rabin')

const common = module.exports

common.rabinPrivateKey = {
  "p": 95710409893817590390139663620366087275247408870842408333898219789050248281757245653962387186577011330413555521601303684960193661446529472595380568496662925717078463086455517438374035528795054110257771412467704924454096429331440714533978386632223042409454305192998811299899291186224795472049889580961886731292907368505099290699371972445350648299305194949955498966079496522896945905590774529349417838259757483085686639857637673528220491859752024165356945769688179n,
  "q": 850361483999592259194197904385613729225847080600107506453692692749565317225938190302437735634758241138444628410968946005140011938713710123917746213155365089324622574228924043794545051050702182655538958610595375336927418648927281663309451280457968105117464051777473418439580755116783253855845974554839203812079902631524368921329232372909802643698042593677933776895789908458900010987268214267756860213459255223762730848062269190843789517079066242842918728372101047n
}
common.rabinPubKey = Rabin.privKeyToPubKey(common.rabinPrivateKey.p, common.rabinPrivateKey.q)
common.oracleNum = 5
common.oracleVerifyNum = 3
common.rabinPubKeyArray = Array(common.oracleNum).fill(common.rabinPubKey)
common.rabinPubKeyIndexArray = []
for (let i = 0; i < common.oracleVerifyNum; i++) {
  common.rabinPubKeyIndexArray.push(i)
}

function loadReleaseDesc(fileName) {
  const filePath = path.join(__dirname, `../out/${fileName}`);
  if (!existsSync(filePath)) {
    throw new Error(`Description file ${filePath} not exist!\nIf You already run 'npm run watch', maybe fix the compile error first!`)
  }
  return JSON.parse(readFileSync(filePath).toString());
}

common.genContract = function(name, use_desc=true, use_release=false) {
  if (use_desc) {
    if (use_release) {
      return buildContractClass(loadReleaseDesc(name + '_release_desc.json'))
    } else {
      return buildContractClass(loadDesc(name + '_desc.json'))
    }
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

    let header = Buffer.alloc(0)
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
  for (let i = 0; i < common.oracleVerifyNum; i++) {
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

common.toBufferLE = function(num, width) {
  const hex = num.toString(16);
  const buffer = Buffer.from(hex.padStart(width * 2, '0').slice(0, width * 2), 'hex');
  buffer.reverse();
  return buffer;
}

common.toBigIntLE = function(buf) {
  const reversed = Buffer.from(buf);
  reversed.reverse();
  const hex = reversed.toString('hex');
  if (hex.length === 0) {
    return BigInt(0);
  }
  return BigInt(`0x${hex}`);
}