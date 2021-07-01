
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

common.rabinPrivateKeys = [
  {
    "p": 95710409893817590390139663620366087275247408870842408333898219789050248281757245653962387186577011330413555521601303684960193661446529472595380568496662925717078463086455517438374035528795054110257771412467704924454096429331440714533978386632223042409454305192998811299899291186224795472049889580961886731292907368505099290699371972445350648299305194949955498966079496522896945905590774529349417838259757483085686639857637673528220491859752024165356945769688179n,
    "q": 850361483999592259194197904385613729225847080600107506453692692749565317225938190302437735634758241138444628410968946005140011938713710123917746213155365089324622574228924043794545051050702182655538958610595375336927418648927281663309451280457968105117464051777473418439580755116783253855845974554839203812079902631524368921329232372909802643698042593677933776895789908458900010987268214267756860213459255223762730848062269190843789517079066242842918728372101047n
  },
  {
    "p": 514130959413096539510620710812221458461066186191922456360304870526648516594373821848498252541366777028270121382578894440311555325172173053954123105540964434359367379107244621114010295504500024178460661564732278783638400392209173884402177293753944249440579628368347573641010690662412381736936332653212244081529173888172317848702493115550252859920880188261967674501158452619833003692963398722507143916027904289669433373041237166569600809214517213577484577543248363n,
    "q": 1859286171864535861956840710926737217632442629773530908450884489875994842504203927907064256734413769968221712753980430079027595837244715075590407273656121646183723234993347252542521523152204824497954917557376501974968155279949434715706343272408085922606599553140950053448561640466915281413870143732477897495472057526027305780672486572510218813484582630396582938374269333100769565734599388223495669370763007744645470476506703819474135947298714275072356448144260679n
  },
  {
    "p": 1311517873564721648993696661720680674433835527675110212235461207575730263803083561043656295528479053198850891292938258829963459377057524561183348302046220942138428316472562995733182421055725304626122128273951444961594321901042256933005209919304386476214488663835119483941894169925480831761930603976068765632542488225618265762292657420293589981403779167967155739821467260636137094644255000356570723544608683813612327244330115177656462148739306274700450570506100867n,
    "q": 856878102308847501877261609426672088906939582365484677471524161279688479969560078345225089421260014439039975890338797397935130756021684919763354490971126449034430455141767231257186963231261022503259531719095581661777685654586892276321774636537035265334227007691506065150518860857948758062892130363734478967327908771139745572741701079034605092780970350940295038281471700014096402841287466018110073585888695436816624923684156785365065401982209436166575055447877807n
  },
  {
    "p": 2368404975736808306097901492782000146880132136710052716879742338294756808885854239975415589945407098674271781604698782201056822663878260285093614565840976324412856845747505161223880092275810108235790050642793045047791725276059857454286069555500986775979917232727767151015517141555939805434762207056729138760613545569560009225442759140927480838980888834454946811972233611655833743541023764189739751873498603110024059922780832528085330376312931177984092425475163163n,
    "q": 994975132914447437549389319157999403287130073311351720805784494849274614367634734328332873886530109087634036094182686171112824397775608037758617491373425832507402977218477086979614948335473864135821126915040253009037286638833327349198767000402435197915547060669189604452877711887613287365868386961306588702838404996030223853759749387870250107701400977694239844772695596687722356064087858215434731021679186143413398079062515080836584412442298917950642057822845159n
  },
  {
    "p": 1648686191618120986314630128174284027721074593046978566316828680992497854297141491903682913507706882254873251861548910918583112204857948506020836962376676512806998133161666996650221312499022519320987232263506233713104904431698790207782898654633570463489129794717782090421254876673002955373299093614492616522659329183879803315342979228406085599989994364196957883207693526072888544796946144351196940074291783752118197246139134249460481800621765236033126433394308411n,
    "q": 1649188802415801035220148983605867905709063370499573898159343986518091208700316480774366832988537074349575752613244823989026136417333821897762086589144565307084900120966060266516493792670450144929344021800203719911977835716532207332651110550476658603669088500696097748575893598079820302124194186867893001217668716001401945842013999349215684017057666971467845656346022723285706330593630773607480733086288980005558288330622147927690003581781767310326596363473202383n
  },
]
common.rabinPubKeyLen = 384
common.oracleNum = 5
common.oracleVerifyNum = 3
common.rabinPubKeyArray = []
for (const rabinPrivateKey of common.rabinPrivateKeys) {
  common.rabinPubKeyArray.push(Rabin.privKeyToPubKey(rabinPrivateKey.p, rabinPrivateKey.q))
}
common.rabinPubKeyVerifyArray = []
common.rabinPubKeyIndexArray = [0, 2, 4]
for (let i = 0; i < common.oracleVerifyNum; i++) {
  common.rabinPubKeyVerifyArray.push(common.rabinPubKeyArray[common.rabinPubKeyIndexArray[i]])
}
common.rabinPubKeyHashArray = Buffer.alloc(0)
for (let i = 0; i < common.oracleNum; i++) {
  common.rabinPubKeyHashArray = Buffer.concat([
    common.rabinPubKeyHashArray,
    bsv.crypto.Hash.sha256ripemd160(common.toBufferLE(common.rabinPubKeyArray[i], common.rabinPubKeyLen))
  ])
}
common.rabinPubKeyHashArrayHash = bsv.crypto.Hash.sha256ripemd160(common.rabinPubKeyHashArray)

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
  let rabinPaddingArray = []
  let rabinSigArray = []
  for (let i = 0; i < common.oracleVerifyNum; i++) {
    const idx = common.rabinPubKeyIndexArray[i]
    const rabinPubKey = common.rabinPubKeyArray[idx]
    const rabinPrivateKey = common.rabinPrivateKeys[idx]
    let rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
    const rabinSign = rabinSignResult.signature
    const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0)
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
