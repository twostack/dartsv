
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/script_chunk.dart';
import 'package:dartsv/src/script/svscript.dart';

class ScriptPattern {

  /**
   * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
   */
  static final int LEGACY_ADDRESS_LENGTH = 20;

  /**
   * <p>
   * Whether or not this is a scriptPubKey representing a P2SH output. In such outputs, the logic that
   * controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
   * spending input to provide a program matching that hash.
   * </p>
   * <p>
   * P2SH is described by <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP16</a>.
   * </p>
   */
  static bool isP2SH(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    // We check for the effective serialized form because BIP16 defines a P2SH output using an exact byte
    // template, not the logical program structure. Thus you can have two programs that look identical when
    // printed out but one is a P2SH script and the other isn't! :(
    // We explicitly test that the op code used to load the 20 bytes is 0x14 and not something logically
    // equivalent like {@code OP_HASH160 OP_PUSHDATA1 0x14 <20 bytes of script hash> OP_EQUAL}
    if (chunks.length != 3)
      return false;
    if (!chunks[0].equalsOpCode(OpCodes.OP_HASH160))
      return false;
    ScriptChunk chunk1 = chunks[1];
    if (chunk1.opcodenum != 0x14)
      return false;
    List<int>? chunk1data = chunk1.buf;
    if (chunk1data == null)
      return false;
    if (chunk1data.length != LEGACY_ADDRESS_LENGTH)
      return false;
    if (!chunks[2].equalsOpCode(OpCodes.OP_EQUAL))
      return false;
    return true;
  }
}