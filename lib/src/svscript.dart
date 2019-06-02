import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'exceptions.dart';
import 'dart:math';

import 'package:dartsv/src/encoding/base58check.dart';

class ScriptChunk{

    List<int> _buf;
    int _len;
    int _opcodenum;

    ScriptChunk(this._buf, this._len, this._opcodenum);

    int get opcodenum => _opcodenum;

    set opcodenum(int value) {
        _opcodenum = value;
    }

    int get len => _len;

    set len(int value) {
        _len = value;
    }

    List<int> get buf => _buf;

    set buf(List<int> value) {
        _buf = value;
    }


}

class SVScript {

    String _script = "";

    List<ScriptChunk> _chunks = List();

    bool _isDataOutFlag = false;

    Uint8List _byteArray = Uint8List(0);

    var _isPubkeyHash = false;


    SVScript.fromChunks(List<ScriptChunk> chunks) {
        this._chunks = chunks;
    }

    SVScript.fromByteArray(Uint8List buffer) {
        this._byteArray = buffer;
    }

    //expect "script" param to be human-readable encoding of opcodes
    SVScript(String script) {
        parse(script);
    }

    /// standard pubkeyScript for P2PKH
    /// FIXME: this constructor name bothers me
    SVScript.buildPublicKeyHashOut(Address fromAddress) {
        var addressLength = HEX
            .decode(fromAddress.address)
            .length;

        var destAddress = fromAddress.address;
        //FIXME: Another hack. For some reason some addresses don't have proper ripemd160 hashes of the hex value. Fix later !
        if (addressLength == 33) {
            addressLength = 20;
            destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
        }
        this._script = sprintf("OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG", [addressLength, destAddress]);
        parse(this._script);
    }

    /// standard sigScript for P2PKH
    /// FIXME: this constructor name bothers me.
    SVScript.buildScriptSig(String signature, String pubKey){
        var pubKeySize = HEX
            .decode(pubKey)
            .length;
        var signatureSize = HEX
            .decode(signature)
            .length;
        this._script = sprintf("%s 0x%s %s 0x%s", [signatureSize, signature, pubKeySize, pubKey]);
        parse(this._script);
    }


    SVScript.buildDataOut(String data) {
        var opcodenum;
        var len = utf8
            .encode(data)
            .length;
        var encodedData = HEX.encode(utf8.encode(data));

        if (len >= 0 && len < OpCodes.OP_PUSHDATA1) {
            opcodenum = len;
        } else if (len < pow(2, 8)) {
            opcodenum = OpCodes.OP_PUSHDATA1;
        } else if (len < pow(2, 16)) {
            opcodenum = OpCodes.OP_PUSHDATA2;
        } else if (len < pow(2, 32)) {
            opcodenum = OpCodes.OP_PUSHDATA4;
        } else {
            throw new ScriptException("You can't push that much data");
        }

        if (len < OpCodes.OP_PUSHDATA1)
            this._script = sprintf("%s %s", [len, encodedData]);
        else
            this._script = sprintf("%s %s %s", [opcodenum, len, encodedData]);

        this._isDataOutFlag = true;

        parse(this._script);
    }


    SVScript.empty(){
        this._script = "";
    }

    Uint8List get buffer {
        return this._byteArray;
    }

    bool get isPubkeyHash => this._isPubkeyHash;

    String toString() {
        return this._script;
    }

    String get script {
        return _script;
    }

    void parse(String script) {
        if (script == null || script.isEmpty) return;

        var tokenList = script.split(" "); //split on spaces

        //encode tokens, leaving non-token elements intact
        var encodedList = tokenList.map((token) {
            var encodedToken = token;
            if (OpCodes.opcodeMap[token.trim()] == null) { //if the token is not in the opCodeMap, it's data

                if (token.indexOf("0x") >= 0 || tokenList.length == 1) { //it's either a 0x-prefixed bit of data, or a hex string
                    encodedToken = token.replaceAll("0x", ""); //strip hex coding identifier if any
                } else {
                    try { //try to parse value as int

                        var tokenVal = int.parse(encodedToken); //FIXME: Dear lord have mercy

                        if (tokenVal >= 1 && tokenVal <= 75) { //if true => this is number-of-following-bytes-to-push
                            encodedToken = tokenVal.toRadixString(16);
                        }
                    } catch (ex) {}
                }
            } else {
                encodedToken = OpCodes.opcodeMap[token.trim()].toRadixString(16);
            }
            return encodedToken;
        });

        this._isPubkeyHash = checkPubkeyHash(encodedList.toList());

        //remove spaces. conc
        String hex = encodedList.fold("", (prev, elem) => prev + elem);

        this._byteArray = HEX.decode(hex);
    }

    //serialize the script to HEX
    String toHex() {
        return HEX.encode(this._byteArray);
    }

    bool isDataOut() => this._isDataOutFlag;

    ///FIXME: This should not be part of SVScript, but a specialization of a PKH Template Script
    ///       Transaction instances will then have to be injected with the specialized Script Template
    ///       which in turn is constructed by a factory method somewhere
    bool checkPubkeyHash(List<String> tokenList) {
        try {
            if (tokenList.length == 4) {
                var signatureBuf = HEX.decode(tokenList[1]);
                var pubkeyBuf = HEX.decode(tokenList[3]);
                if (signatureBuf[0] == 0x30) {
                    var version = pubkeyBuf[0];
                    if ((version == 0x04 || version == 0x06 || version == 0x07) && pubkeyBuf.length == 65) {
                        return true;
                    } else if ((version == 0x03 || version == 0x02) && pubkeyBuf.length == 33) {
                        return true;
                    }
                }
            }

            return false;
        } catch (ex) {
            return false;
        }
    }

    bool isPushOnly() {
        return false;
    }

    bool isScriptHashOut() {
        return false;
    }

    List<ScriptChunk> get chunks => _chunks;

  bool checkMinimalPush(int i) {
      return false;
  }

  void findAndDelete(SVScript tmpScript) {

  }



}

