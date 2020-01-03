import 'package:dartsv/dartsv.dart';
import 'package:bip39/bip39.dart' as bip39; //third-party library. NOT PART OF DART-SV
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';
import 'package:cli_example/BitIndex.dart';

class MyWallet {


    HDPrivateKey _hdMaster;

    SVPrivateKey _walletPrivKey, _walletPrivKey2;
    SVPublicKey _walletPubKey, _walletPubKey2;
    Address _spendingAddress, _receivingAddress;  //we will spend money from _address to _address2

    //From bip39 Library (bip39 not currently implemented in dartsv
    String generateSeedWords() => bip39.generateMnemonic();

    String retrieveSeed(String mnemonic) => bip39.mnemonicToSeedHex(mnemonic);

    bool isValidMnemonic(String mnemonic) => bip39.validateMnemonic(mnemonic);

    Address getAddress(SVPublicKey publicKey) {
        var address = publicKey.toAddress(NetworkType.TEST);
        print(sprintf("Receiving Address: %s", [address.toString()]));

        return address;
    }

    MyWallet.fromSeed(String mnemonic){

        var seedVector = retrieveSeed(mnemonic);

        //retrieve Master HD Key from seed mnemonic
        this._hdMaster = HDPrivateKey.fromSeed(seedVector, NetworkType.TEST);

        //derive a new hardened keypair from our Master Key
        HDPrivateKey xprivateKey = HDPrivateKey.fromXpriv(this._hdMaster.xprivkey).deriveChildKey("m/44'/1'/1'/0'");
        xprivateKey.networkType = NetworkType.TEST;
        HDPublicKey xpublicKey = xprivateKey.hdPublicKey;

        this._walletPrivKey = xprivateKey.privateKey;
        this._walletPubKey = SVPublicKey.fromHex(HEX.encode(xpublicKey.keyBuffer));

        //derive a second hardened keypair from our Master key
        HDPrivateKey xprivateKey2 = HDPrivateKey.fromXpriv(this._hdMaster.xprivkey).deriveChildKey("m/44'/1'/1'/1'");
        xprivateKey2.networkType = NetworkType.TEST;
        HDPublicKey xpublicKey2 = xprivateKey2.hdPublicKey;

        this._walletPrivKey2 = xprivateKey2.privateKey;
        this._walletPubKey2 = SVPublicKey.fromHex(HEX.encode(xpublicKey2.keyBuffer));

        _receivingAddress = this._walletPrivKey.toAddress(networkType: NetworkType.TEST);
        _spendingAddress= this._walletPrivKey2.toAddress(networkType: NetworkType.TEST);

    }


    String createWalletTxn(Address address, List<TransactionInput> utxosToSpendFrom, BigInt amount ){


        var transaction = new Transaction()
            .spendFromInputs(utxosToSpendFrom)
            .spendTo(address, amount)
            .sendChangeTo(_receivingAddress) // spend change to myself
            .withFeePerKb(100000)
            .signWith(this._walletPrivKey, sighashType: SighashType.SIGHASH_ALL | SighashType.SIGHASH_FORKID);

        return transaction.serialize();

    }

    Address get spendingAddress => this._spendingAddress;
    Address get receivingAddress =>  this._receivingAddress;

    /*
        When sending money we need to
        1) Get a list of UTXOs we can spend from
        2) Generate a list of UTXOs that has total amount > sending amount
     */
    Future<String> sendMoney(Address address, BigInt amount) async {

        var bi = BitIndex(NetworkType.TEST);

        //query the BitIndex API for UTXOs matching our testnet faucet receiving address
        Future<List<TransactionOutput>> futureOutputs = bi.getUTXOs(this._receivingAddress);

        List<TransactionInput> inputs = List<TransactionInput>();
        Future<String> res = futureOutputs.then((List<TransactionOutput> outputs){

            //sort the UTXOs according to amount of satoshis they contain
            outputs.sort((a, b) => a.satoshis.compareTo(b.satoshis));
            BigInt total = BigInt.zero;

            //find minimum viable spending-set of UTXOs
            for (var output in outputs) {
                total = total + output.satoshis;
                var txout = TransactionInput(output.transactionId, output.outputIndex, output.script, output.satoshis, Transaction.NLOCKTIME_MAX_VALUE);
                inputs.add(txout);
                if (total >= amount){
                    var txn = createWalletTxn(address, inputs, amount);
                    bi.sendTransaction(txn);
                    return txn;
                }

            };

            return "";
        });


        return  res;
    }

    SVPublicKey get walletPubKey => _walletPubKey;


}
