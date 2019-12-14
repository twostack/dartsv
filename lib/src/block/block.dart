
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/transaction/transaction.dart';
import 'package:hex/hex.dart';
import 'blockheader.dart';

class Block {

  List<int> _buffer;
  List<Transaction> _transactions;
  BlockHeader _header;

  Block(BlockHeader header, List<Transaction> transactions){
    this._header = header;
    this._transactions = transactions;
  }


  Block.fromBuffer(List<int> blockbuf) {

    if (blockbuf.isEmpty){
      throw new BlockException('Empty blocks are not allowed');
    }
    this._buffer = blockbuf;
  }

  get header => this._header;

  get transactions => this._transactions;

  String toHex() {
    return HEX.encode(this._buffer);
  }

}