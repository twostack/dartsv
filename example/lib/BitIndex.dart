

import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:io';
import 'package:dartsv/dartsv.dart';


/* URI and Response for Address API call to BitIndex
https://api.bitindex.network/api/v3/test/addr/{address}
{
  "addrStr": "mhoo3LWPU2XYLMLyBv1pyvC2trzZ4rVxXU",
  "balance": 0.32,
  "balanceSat": 32000000,
  "totalReceived": 0.32,
  "totalReceivedSat": 32000000,
  "totalSent": 0,
  "totalSentSat": 0,
  "unconfirmedBalance": 0,
  "unconfirmedBalanceSat": 0,
  "unconfirmedTxApperances": 0,
  "txApperances": 1,
  "transactions": [
    "8f26257873b6a6b43cb7d93802fcb9444a4cf35160bfe014ab41645e556d346c"
  ]
}
*/

class BitIndex {

    //******* DANGER *******
    //DO NOT RE-USE THIS KEY !
    //******* DANGER *******
    String _API_KEY = "8Uw3T3bcjJn34X8NWPv5P5D4d1BojPUZEh17CsZsMBuNt6U17TA2Vxb56artKgoHxr";
    var _networkType;


    BitIndex (this._networkType);

/*

BELOW AN EXAMPLE JSON RETURN FROM BITINDEX UTXO QUERY
============================================================
https://api.bitindex.network/api/v3/test/addr/{address}/utxo
[
  {
    "address": "mhoo3LWPU2XYLMLyBv1pyvC2trzZ4rVxXU",
    "txid": "8f26257873b6a6b43cb7d93802fcb9444a4cf35160bfe014ab41645e556d346c",
    "vout": 0,
    "amount": 0.32,
    "satoshis": 32000000,
    "value": 32000000,
    "height": 1302757,
    "confirmations": 15,
    "scriptPubKey": "76a914191f99293aedd9f66e090e296abe2c64cabdbc5788ac"
  }
]
*/
    Future<List<TransactionOutput>> getUTXOs(Address address) async {

        var host = "api.bitindex.network";
        var path = "/api/v3/test/addr/${address.toString()}/utxo"; //UTXO query for a specific address

        var request = await HttpClient().getUrl(Uri.parse("https://${host}${path}"))
                                        ..headers.contentType = ContentType.json
                                        ..headers.set("Accept", ContentType.json.toString());

        HttpClientResponse response = await request.close();
        String body = await response.transform(utf8.decoder).fold("", (prev, elem) => prev+elem);

        var utxoList = json.decode(body) as List;

//        print(body);

        List<TransactionOutput> utxos = utxoList.map((utxo){
            var txOut = TransactionOutput(scriptBuilder: P2PKHLockBuilder(null));
            txOut.satoshis = BigInt.from(utxo["satoshis"]);
            txOut.transactionId = utxo["txid"];
            txOut.outputIndex = utxo["vout"];
            txOut.script = SVScript.fromHex(utxo["scriptPubKey"]);
            return txOut;
        }).toList();

        return utxos;

    }

    //Accepts a raw TXN and sends it to the BSV testnet via BitIndex
    sendTransaction(String rawTxn) async {

        var host = "https://api.bitindex.network";
        var path = "/api/v3/test/tx/send"; //UTXO query for a specific address

        var postData = {"rawtx" : rawTxn};

        var response = await http.post("${host}${path}", body: json.encode(postData), headers: {
            "Content-Type" : "application/json",
            "Accept" : "application/json"
        });

        print(response.body);

    }

}