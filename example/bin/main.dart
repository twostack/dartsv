import 'package:cli_example/MyWallet.dart';

main(List<String> arguments) async {

    //********
    //WARNING ! : DON'T RE-USE THIS SEED_WORD SEQUENCE IN YOUR PROJECT (or worse, MAINNET) ! YOU WILL LOSE MONEY !
    //********
    var MNEMONIC = 'edge eagle blue panda zone tiger emerge trial limit royal average basket';

    var wallet = MyWallet.fromSeed(MNEMONIC);

    var faucetAddress = wallet.receivingAddress;  //we "receive" faucet funds here
    var spendingAddress = wallet.spendingAddress;   //our second address

    print("Receiving Address : ${faucetAddress} "); //send Faucet coins here
    print("Spending Address : ${spendingAddress}"); //send received coins here (other key/address we control)

    try {
        var txn = await wallet.sendMoney(spendingAddress, BigInt.from(10000)); //send 10k satoshis to ourself
        print(txn);
    }catch(ex){
        print(ex.toString());
    }

}
