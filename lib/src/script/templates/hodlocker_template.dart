import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/script_template.dart';
import 'package:hex/hex.dart';

/// Implementation of the HODLocker script template for time-locked funds
class HODLockerTemplate implements ScriptTemplate {
  static const String TEMPLATE_NAME = "HODLocker";

  // Constants used in the HODLocker script
  // static const String FIRST_CONSTANT = "97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026";
  // static const String SECOND_CONSTANT = "02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382";
  // static const String THIRD_CONSTANT = "1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c";

  // Template ASM for the HODLocker script
  // static const String OUTPUT_TEMPLATE_ASM = "$FIRST_CONSTANT $SECOND_CONSTANT $THIRD_CONSTANT 0 0 <ownerPubkeyHash> <lockHeight> OP_NOP 0 OP_PICK 0065cd1d OP_LESSTHAN OP_VERIFY";

  static const String OUTPUT_TEMPLATE_ASM =
      "97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026 02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382 1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c 0 0 <ownerPubkeyHash> <lockHeight> OP_NOP 0 OP_PICK 0065cd1d OP_LESSTHAN OP_VERIFY 0 OP_PICK OP_4 OP_ROLL OP_DROP OP_3 OP_ROLL OP_3 OP_ROLL OP_3 OP_ROLL OP_1 OP_PICK OP_3 OP_ROLL OP_DROP OP_2 OP_ROLL OP_2 OP_ROLL OP_DROP OP_DROP OP_NOP OP_5 OP_PICK 41 OP_NOP OP_1 OP_PICK OP_7 OP_PICK OP_7 OP_PICK 0ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800 6c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810 OP_9 OP_PICK OP_6 OP_PICK OP_NOP OP_6 OP_PICK OP_HASH256 0 OP_PICK OP_NOP 0 OP_PICK OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_7 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_NOP OP_3 OP_PICK OP_6 OP_PICK OP_4 OP_PICK OP_7 OP_PICK OP_MUL OP_ADD OP_MUL 414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00 OP_1 OP_PICK OP_1 OP_PICK OP_NOP OP_1 OP_PICK OP_1 OP_PICK OP_MOD 0 OP_PICK 0 OP_LESSTHAN OP_IF 0 OP_PICK OP_2 OP_PICK OP_ADD OP_ELSE 0 OP_PICK OP_ENDIF OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_2 OP_ROLL OP_DROP OP_1 OP_ROLL OP_1 OP_PICK OP_1 OP_PICK OP_2 OP_DIV OP_GREATERTHAN OP_IF 0 OP_PICK OP_2 OP_PICK OP_SUB OP_2 OP_ROLL OP_DROP OP_1 OP_ROLL OP_ENDIF OP_3 OP_PICK OP_SIZE OP_NIP OP_2 OP_PICK OP_SIZE OP_NIP OP_3 OP_PICK 20 OP_NUM2BIN OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT 20 OP_2 OP_PICK OP_SUB OP_SPLIT OP_NIP OP_4 OP_3 OP_PICK OP_ADD OP_2 OP_PICK OP_ADD 30 OP_1 OP_PICK OP_CAT OP_2 OP_CAT OP_4 OP_PICK OP_CAT OP_8 OP_PICK OP_CAT OP_2 OP_CAT OP_3 OP_PICK OP_CAT OP_2 OP_PICK OP_CAT OP_7 OP_PICK OP_CAT 0 OP_PICK OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP 0 OP_PICK OP_7 OP_PICK OP_CHECKSIG OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK OP_4 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK OP_8 OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP 0065cd1d OP_LESSTHAN OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK 28 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK 2c OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP ffffffff00 OP_LESSTHAN OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK OP_4 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK OP_8 OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP OP_2 OP_PICK OP_GREATERTHANOREQUAL OP_VERIFY OP_6 OP_PICK OP_HASH160 OP_1 OP_PICK OP_EQUAL OP_VERIFY OP_7 OP_PICK OP_7 OP_PICK OP_CHECKSIG OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP";

  @override
  String get name => TEMPLATE_NAME;

  @override
  bool matches(SVScript script) {
    return ScriptPattern.isHODLocker(script);
  }

  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    if (!params.containsKey('pubKeyHash') ||
        !params.containsKey('lockHeight')) {
      throw ArgumentError(
          'HODLocker template requires pubKeyHash and lockHeight parameters');
    }

    final pubKeyHash = params['pubKeyHash'];
    final lockHeight = params['lockHeight'];

    List<int> pubKeyHashBytes;

    if (pubKeyHash is String) {
      // Assume it's a hex string
      pubKeyHashBytes = HEX.decode(pubKeyHash);
    } else if (pubKeyHash is Uint8List) {
      pubKeyHashBytes = pubKeyHash.toList();
    } else if (pubKeyHash is List<int>) {
      pubKeyHashBytes = pubKeyHash;
    } else {
      throw ArgumentError(
          'pubKeyHash must be a hex String, Uint8List, or List<int>');
    }

    // Validate pubKeyHash length
    if (pubKeyHashBytes.length != 20) {
      throw ArgumentError('pubKeyHash must be 20 bytes');
    }

    BigInt lockHeightValue;

    if (lockHeight is BigInt) {
      lockHeightValue = lockHeight;
    } else if (lockHeight is int) {
      lockHeightValue = BigInt.from(lockHeight);
    } else if (lockHeight is String) {
      lockHeightValue = BigInt.parse(lockHeight);
    } else {
      throw ArgumentError('lockHeight must be a BigInt, int, or String');
    }

    return HODLockerLockingScriptBuilder(pubKeyHashBytes, lockHeightValue);
  }

  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    // HODLocker unlocking script would be complex and depends on whether
    // the time lock has expired or not. For simplicity, we'll throw an
    // UnsupportedError for now.
    throw UnsupportedError(
        'HODLocker unlocking script creation is not yet supported');
  }

  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // This would require checking if any of the available keys hash to the pubKeyHash
    // in the script and if the current block height is greater than the lockHeight.
    // For simplicity, we'll return false for now.
    return false;
  }

  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    if (!matches(script)) {
      throw ArgumentError('Script does not match HODLocker template');
    }

    final chunks = script.chunks;

    // Extract the pubKeyHash and lockHeight
    final pubKeyHash = chunks[5].buf!;

    // Extract lockHeight - this is a number
    final lockHeightBytes = chunks[6].buf!;
    final lockHeight = castToBigInt(lockHeightBytes, false);

    return {
      'type': TEMPLATE_NAME,
      'pubKeyHash': pubKeyHash,
      'lockHeight': lockHeight,
    };
  }
}

/// HODLocker Locking Script Builder
class HODLockerLockingScriptBuilder extends LockingScriptBuilder {
  final List<int> _pubKeyHash;
  final BigInt _lockHeight;

  HODLockerLockingScriptBuilder(this._pubKeyHash, this._lockHeight);

  @override
  SVScript getScriptPubkey() {
    if (_lockHeight == BigInt.zero || _pubKeyHash.isEmpty) {
      throw ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE,
          "Missing lockheight and/or pubkeyHash");
    }

    // Replace the placeholders in the template ASM
    var scriptAsm = HODLockerTemplate.OUTPUT_TEMPLATE_ASM.replaceFirst(
        "<lockHeight>",
        ScriptBuilder()
            .number(_lockHeight.toInt())
            .build()
            .toString(type: 'asm'));

    scriptAsm = scriptAsm.replaceFirst(
        "<ownerPubkeyHash>",
        ScriptBuilder()
            .addData(Uint8List.fromList(_pubKeyHash))
            .build()
            .toString(type: 'asm'));

    return SVScript.fromASM(scriptAsm);
  }

  @override
  void parse(SVScript script) {
    if (!ScriptPattern.isHODLocker(script)) {
      throw ArgumentError('Script is not a valid HODLocker script');
    }

    // No need to extract script info or set fields since they're final,
    // but in a real implementation you might want to handle this differently
    // by using the extracted values from the script
  }
}
