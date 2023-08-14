import 'package:dartsv/dartsv.dart';

class TransactionOutpoint {
  String transactionId;
  int outputIndex;
  BigInt satoshis;
  SVScript lockingScript;

  TransactionOutpoint(this.transactionId, this.outputIndex, this.satoshis, this.lockingScript);

}
