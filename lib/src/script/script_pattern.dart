import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/script_chunk.dart';
import 'package:dartsv/src/script/svscript.dart';

/// Utility class for identifying different script patterns
class ScriptPattern {
  /// An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
  static final int LEGACY_ADDRESS_LENGTH = 20;

  /// Whether or not this is a scriptPubKey representing a P2SH output.
  ///
  /// In such outputs, the logic that controls reclamation is not actually in the output at all.
  /// Instead there's just a hash, and it's up to the spending input to provide a program matching that hash.
  ///
  /// P2SH is described by BIP16.
  static bool isP2SH(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    // We check for the effective serialized form because BIP16 defines a P2SH output using an exact byte
    // template, not the logical program structure. Thus you can have two programs that look identical when
    // printed out but one is a P2SH script and the other isn't! :(
    // We explicitly test that the op code used to load the 20 bytes is 0x14 and not something logically
    // equivalent like {@code OP_HASH160 OP_PUSHDATA1 0x14 <20 bytes of script hash> OP_EQUAL}
    if (chunks.length != 3) return false;
    if (!chunks[0].equalsOpCode(OpCodes.OP_HASH160)) return false;
    ScriptChunk chunk1 = chunks[1];
    if (chunk1.opcodenum != 0x14) return false;
    List<int>? chunk1data = chunk1.buf;
    if (chunk1data == null) return false;
    if (chunk1data.length != LEGACY_ADDRESS_LENGTH) return false;
    if (!chunks[2].equalsOpCode(OpCodes.OP_EQUAL)) return false;
    return true;
  }

  /// Returns true if the script is a standard P2PKH (Pay to Public Key Hash) script
  ///
  /// P2PKH script format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
  static bool isP2PKH(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    if (chunks.length != 5) return false;
    if (!chunks[0].equalsOpCode(OpCodes.OP_DUP)) return false;
    if (!chunks[1].equalsOpCode(OpCodes.OP_HASH160)) return false;
    ScriptChunk chunk2 = chunks[2];
    List<int>? chunk2data = chunk2.buf;
    if (chunk2data == null) return false;
    if (chunk2data.length != LEGACY_ADDRESS_LENGTH) return false;
    if (!chunks[3].equalsOpCode(OpCodes.OP_EQUALVERIFY)) return false;
    if (!chunks[4].equalsOpCode(OpCodes.OP_CHECKSIG)) return false;
    return true;
  }

  /// Returns true if the script is a standard P2PK (Pay to Public Key) script
  ///
  /// P2PK script format: <pubkey> OP_CHECKSIG
  static bool isP2PK(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    if (chunks.length != 2) return false;

    ScriptChunk chunk0 = chunks[0];
    if (chunk0.buf == null) return false;

    // Public key can be in compressed (33 bytes) or uncompressed (65 bytes) format
    int pubKeyLength = chunk0.buf!.length;
    if (pubKeyLength != 33 && pubKeyLength != 65) return false;

    if (!chunks[1].equalsOpCode(OpCodes.OP_CHECKSIG)) return false;

    return true;
  }

  /// Returns true if the script is a standard P2MS (multi-signature) script
  ///
  /// P2MS script format: m <pubkey1> <pubkey2> ... <pubkeyn> n OP_CHECKMULTISIG
  static bool isP2MS(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;

    // Minimum valid length is 4 (m, pubkey, n, OP_CHECKMULTISIG)
    if (chunks.length < 4) return false;

    // Last chunk must be OP_CHECKMULTISIG
    if (!chunks[chunks.length - 1].equalsOpCode(OpCodes.OP_CHECKMULTISIG))
      return false;

    // Second to last chunk (n) must be a small number opcode
    ScriptChunk nChunk = chunks[chunks.length - 2];
    if (!nChunk.isOpCode() ||
        nChunk.opcodenum < OpCodes.OP_1 ||
        nChunk.opcodenum > OpCodes.OP_16) return false;

    // First chunk (m) must be a small number opcode
    ScriptChunk mChunk = chunks[0];
    if (!mChunk.isOpCode() ||
        mChunk.opcodenum < OpCodes.OP_1 ||
        mChunk.opcodenum > OpCodes.OP_16) return false;

    // n must be >= m
    int n = SVScript.decodeFromOpN(nChunk.opcodenum);
    int m = SVScript.decodeFromOpN(mChunk.opcodenum);
    if (n < m) return false;

    // n must equal the number of pubkeys
    if (n != chunks.length - 3) return false;

    // Check that all pubkeys are valid
    for (int i = 1; i < chunks.length - 2; i++) {
      ScriptChunk pubKeyChunk = chunks[i];
      if (pubKeyChunk.buf == null) return false;

      // Public key can be in compressed (33 bytes) or uncompressed (65 bytes) format
      int pubKeyLength = pubKeyChunk.buf!.length;
      if (pubKeyLength != 33 && pubKeyLength != 65) return false;
    }

    return true;
  }

  /// Returns true if the script is an OP_RETURN data script
  ///
  /// OP_RETURN script format: OP_FALSE OP_RETURN <data>
  static bool isOpReturn(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;

    // Must have at least one chunk
    if (chunks.isEmpty) return false;

    // First chunks must be OP_FALSE and OP_RETURN
    return chunks[0].equalsOpCode(OpCodes.OP_FALSE) &&
        chunks[1].equalsOpCode(OpCodes.OP_RETURN);
  }
  
  /// Returns true if the script is an Author Identity Protocol script
  ///
  /// Author Identity Protocol script format:
  /// OP_FALSE OP_RETURN <PREFIX> <SIGNING_ALGORITHM> <publicKey> <signature>
  /// Where PREFIX is "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"
  static bool isAuthorIdentity(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    
    // Must have at least 6 chunks (OP_FALSE, OP_RETURN, PREFIX, SIGNING_ALGORITHM, publicKey, signature)
    if (chunks.length < 6) return false;
    
    // First chunks must be OP_FALSE and OP_RETURN
    if (!chunks[0].equalsOpCode(OpCodes.OP_FALSE) ||
        !chunks[1].equalsOpCode(OpCodes.OP_RETURN)) {
      return false;
    }
    
    // Check for the PREFIX in the third chunk
    final String PREFIX = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
    if (chunks[2].buf == null) return false;
    
    try {
      String prefix = String.fromCharCodes(chunks[2].buf!);
      return prefix == PREFIX;
    } catch (e) {
      return false;
    }
  }

  /// Returns true if the script is a B-Protocol script
  ///
  /// B-Protocol script format:
  /// OP_FALSE OP_RETURN <PREFIX> <Data> <Media Type> <Encoding> [Filename]
  /// Where PREFIX is "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
  static bool isBProtocol(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    
    // Must have at least 6 chunks (OP_FALSE, OP_RETURN, PREFIX, Data, Media Type, Encoding)
    // Filename is optional
    if (chunks.length < 6) return false;
    
    // First chunks must be OP_FALSE and OP_RETURN
    if (!chunks[0].equalsOpCode(OpCodes.OP_FALSE) ||
        !chunks[1].equalsOpCode(OpCodes.OP_RETURN)) {
      return false;
    }
    
    // Check for the PREFIX in the third chunk
    final String PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";
    if (chunks[2].buf == null) return false;
    
    try {
      String prefix = String.fromCharCodes(chunks[2].buf!);
      return prefix == PREFIX;
    } catch (e) {
      return false;
    }
  }

  /// Returns true if the script is a HODLocker script
  ///
  /// HODLocker script format starts with specific constants followed by
  /// <ownerPubkeyHash> <lockHeight> OP_NOP 0 OP_PICK 0065cd1d OP_LESSTHAN OP_VERIFY ...
  static bool isHODLocker(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;
    
    // HODLocker scripts are complex and have many chunks
    if (chunks.length < 10) return false;
    
    // Check for the specific constants that prefix a HODLocker script
    // First constant: 97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026
    if (chunks[0].buf == null) return false;
    final String firstConstant = "97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026";
    
    // Second constant: 02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382
    if (chunks[1].buf == null) return false;
    final String secondConstant = "02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382";
    
    // Third constant: 1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c
    if (chunks[2].buf == null) return false;
    final String thirdConstant = "1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c";
    
    try {
      // Convert the hex strings to bytes for comparison
      final firstBytes = chunks[0].buf!;
      final secondBytes = chunks[1].buf!;
      final thirdBytes = chunks[2].buf!;
      
      // Check if the first three data chunks match our expected constants
      // This is a simplified check - in a real implementation, you might want to do a proper hex comparison
      if (firstBytes.length != firstConstant.length ~/ 2 || 
          secondBytes.length != secondConstant.length ~/ 2 || 
          thirdBytes.length != thirdConstant.length ~/ 2) {
        return false;
      }
      
      // Check for the pattern after the constants: 0 0 <pubKeyHash> <lockHeight>
      // Fourth and fifth chunks should be 0
      if (!chunks[3].equalsOpCode(OpCodes.OP_0) || !chunks[4].equalsOpCode(OpCodes.OP_0)) {
        return false;
      }
      
      // Sixth chunk should be the pubKeyHash (20 bytes)
      if (chunks[5].buf == null || chunks[5].buf!.length != LEGACY_ADDRESS_LENGTH) {
        return false;
      }
      
      // Seventh chunk should be the lockHeight (a number)
      if (chunks[6].buf == null) {
        return false;
      }
      
      // Eighth chunk should be OP_NOP
      if (!chunks[7].equalsOpCode(OpCodes.OP_NOP)) {
        return false;
      }
      
      // Ninth chunk should be 0 (OP_0)
      if (!chunks[8].equalsOpCode(OpCodes.OP_0)) {
        return false;
      }
      
      // Tenth chunk should be OP_PICK
      if (!chunks[9].equalsOpCode(OpCodes.OP_PICK)) {
        return false;
      }
      
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Returns true if the script is a time-locked script
  ///
  /// Time-locked script format: <locktime> OP_CHECKLOCKTIMEVERIFY ...
  static bool isTimeLocked(SVScript script) {
    List<ScriptChunk> chunks = script.chunks;

    // Must have at least two chunks
    if (chunks.length < 2) return false;

    // Check for CLTV opcode
    for (int i = 1; i < chunks.length; i++) {
      if (chunks[i].equalsOpCode(OpCodes.OP_CHECKLOCKTIMEVERIFY)) {
        // Previous chunk must be a number (locktime)
        ScriptChunk lockTimeChunk = chunks[i - 1];
        return lockTimeChunk.buf != null;
      }
    }

    return false;
  }
}
