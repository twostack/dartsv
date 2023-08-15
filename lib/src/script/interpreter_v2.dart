/*
 * Copyright 2023 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/encoding/utils.dart';
import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/script/script_chunk.dart';
import 'package:dartsv/src/script/script_error.dart';
import 'package:dartsv/src/script/svscript.dart';

import '../transaction/script_builder.dart';
import '../transaction/transaction.dart';

class ByteArrayItem extends LinkedListEntry<ByteArrayItem> {
  Uint8List buffer;

  ByteArrayItem(this.buffer);
}

class BoolItem extends LinkedListEntry<BoolItem> {
  bool option;

  BoolItem(this.option);
}

class Interpreter {

  // Maximum script number length after Genesis
  //consensus.h in node client
  /** 1KB */
  static final int ONE_KILOBYTE = 1000;

  //     static final int MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
  static final int MAX_SCRIPT_ELEMENT_SIZE = 2147483647; // 2Gigabytes after Genesis - (2^31 -1)
//     static final int MAX_OPS_PER_SCRIPT = 201;

  // Maximum number of non-push operations per script after GENESIS
  // Maximum number of non-push operations per script before GENESIS
  static final int MAX_OPS_PER_SCRIPT_BEFORE_GENESIS = 500;

// Maximum number of non-push operations per script after GENESIS
  static int UINT32_MAX = 4294967295;
  static final int MAX_OPS_PER_SCRIPT_AFTER_GENESIS = UINT32_MAX;

  static final int MAX_STACK_SIZE = 1000;
  static final int DEFAULT_MAX_NUM_ELEMENT_SIZE = 4;
  static final int MAX_PUBKEYS_PER_MULTISIG = 20;
  static final int MAX_SCRIPT_SIZE = 10000;
  static final int SIG_SIZE = 75;

  /** Max number of sigops allowed in a standard p2sh redeem script */
  static final int MAX_P2SH_SIGOPS = 15;

  // Maximum script number length after Genesis
  static final int MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS = 750 * ONE_KILOBYTE;

  static final int MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS = 4;
  static final int DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS = 250 * 1024;

  static final int MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

  ////////////////////// Script verification and helpers ////////////////////////////////

  static bool castToBool(Uint8List data) {
    for (int i = 0; i < data.length; i++) {
      // "Can be negative zero" - Bitcoin Core (see OpenSSL's BN_bn2mpi)
      if (data[i] != 0)
        return !(i == data.length - 1 && (data[i] & 0xFF) == 0x80);
    }
    return false;
  }

  /**
   * Cast a script chunk to a BigInt.
   *
   * @see #castToBigInt(Uint8List, int, bool) for values with different maximum
   * sizes.
   * @throws ScriptException if the chunk is longer than 4 bytes.
   */
  BigInt castToBigInt32(Uint8List chunk, final bool requireMinimal) {
    return castToBigInt(chunk, 4, requireMinimal);
  }

  /**
   * Cast a script chunk to a BigInt. Normally you would want
   * {@link #castToBigInt(Uint8List, bool)} instead, this is only for cases where
   * the normal maximum length does not apply (i.e. CHECKLOCKTIMEVERIFY).
   *
   * @param maxLength the maximum length in bytes.
   * @param requireMinimal check if the number is encoded with the minimum possible number of bytes
   * @throws ScriptException if the chunk is inter than the specified maximum.
   */
  /* package  */
  castToBigInt(final Uint8List chunk, final int maxLength, final bool requireMinimal) {
    if (chunk.length > maxLength) {
      throw ScriptException(ScriptError.SCRIPT_ERR_NUMBER_OVERFLOW.mnemonic + "Script attempted to use an integer larger than ${maxLength} bytes");
    }

    if (requireMinimal && chunk.length > 0) {
      // Check that the number is encoded with the minimum possible
      // number of bytes.
      //
      // If the most-significant-byte - excluding the sign bit - is zero
      // then we're not minimal. Note how this test also rejects the
      // negative-zero encoding, 0x80.
      if ((chunk[chunk.length - 1] & 0x7f) == 0) {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if (chunk.length <= 1 || (chunk[chunk.length - 2] & 0x80) == 0) {
          throw ScriptException(ScriptError.SCRIPT_ERR_NUMBER_MINENCODE, "non-minimally encoded script number");
        }
      }
    }

    return decodeMPI(Uint8List.fromList(chunk.reversed.toList()), false);
  }


  /**
   * Gets the count of regular SigOps in the script program (counting multisig ops as 20)
   */
  int getSigOpCount(Uint8List program) {
    SVScript script = ScriptBuilder().build();
    try {
      script = SVScript.fromByteArray(program);
    } on ScriptException catch (e) {
      // Ignore errors and count up to the parse-able length
    }
    return SVScript.getSigOpCount(script.chunks, false);
  }

  static bool isOpcodeDisabled(int opcode, Set<VerifyFlag> verifyFlags) {
    switch (opcode) {
      case OpCodes.OP_2MUL:
      case OpCodes.OP_2DIV:
      //disabled codes
        return true;

      default:
      //not an opcode that was ever disabled
        break;
    }
    return false;
  }


//    /**
//     * Exposes the script interpreter.
//     * is useful if you need more precise control or access to the final state of the stack. This interface is very
//     * likely to change in future.
//     */
//     static void executeScript(@Nullable Transaction txContainingThis, int index,
//                                     Script script, LinkedList<Uint8List> stack, Coin value, Set<VerifyFlag> verifyFlags) throws ScriptException {
//        executeScript(txContainingThis,index, script, stack, value, verifyFlags /*, null*/);
//    }


  /**
   * Exposes the script interpreter. Normally you should not use this directly, instead use
   * is useful if you need more precise control or access to the final state of the stack. This interface is very
   * likely to change in future.
   */
  void executeScript(Transaction? txContainingThis, int index,
      SVScript script, LinkedList<ByteArrayItem> stack, BigInt value, Set<VerifyFlag> verifyFlags /*, ScriptStateListener scriptStateListener*/) {
    int opCount = 0;
    int lastCodeSepLocation = 0;
    final bool enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);
    final bool utxoAfterGenesis = verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS);
    final int maxScriptNumLength = getMaxScriptNumLength(utxoAfterGenesis);


    var altstack = LinkedList<ByteArrayItem>();
    var ifStack = LinkedList<BoolItem>();
    var elseStack = LinkedList<BoolItem>();

    bool nonTopLevelReturnAfterGenesis = false;

    int nextLocationInScript = 0;
    for (ScriptChunk chunk in script.chunks) {
      int opcode = chunk.opcodenum;

      // Do not execute instructions if Genesis OpCodes.OP_RETURN was found in executed branches.
      bool shouldExecute = !ifStack.contains(false) && (!nonTopLevelReturnAfterGenesis || opcode == OpCodes.OP_RETURN);
      nextLocationInScript += chunk.size();

      // Check stack element size
      if (chunk.buf != null && (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && chunk.buf.length > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
        throw ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE.mnemonic + "-Attempted to push a data string larger than 520 bytes");

      // Note how OpCodes.OP_RESERVED does not count towards the opcode limit.
      if (opcode > OpCodes.OP_16) {
        opCount++;
        if (!isValidMaxOpsPerScript(opCount, utxoAfterGenesis))
          throw ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT.mnemonic + " -More script operations than is allowed");
      }

      // Disabled opcodes.
      if (isOpcodeDisabled(opcode, verifyFlags) && (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) || shouldExecute)) {
        throw ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE.mnemonic + "-Script included a disabled Script Op.");
      }

      if (shouldExecute && OpCodes.OP_0 <= opcode && opcode <= OpCodes.OP_PUSHDATA4) {
        // Check minimal push
        if (verifyFlags.contains(VerifyFlag.MINIMALDATA) && !chunk.checkMinimalPush())
          throw ScriptException(ScriptError.SCRIPT_ERR_MINIMALDATA.mnemonic + "Script included a not minimal push operation.");

        if (opcode == OpCodes.OP_0) {
          stack.add(ByteArrayItem(([])));
        } else {
          stack.add(ByteArrayItem(chunk.buf));
        }
      } else if (shouldExecute || (OpCodes.OP_IF <= opcode && opcode <= OpCodes.OP_ENDIF)) {
        switch (opcode) {
          case OpCodes.OP_IF:
          case OpCodes.OP_NOTIF:
            bool fValue = false;
            if (shouldExecute) {
              if (stack.length < 1) {
                throw ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL.mnemonic + "Attempted OpCodes.OP_IF on an empty stack");
              }

              Uint8List stacktop = stack.last.buffer;
              if (verifyFlags.contains(VerifyFlag.MINIMALIF)) {
                if (stacktop.length > 1) {
                  throw ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF.mnemonic + "Argument for OpCodes.OP_IF/NOT_IF must be 0x01 or empty");
                }

                if (stacktop.length == 1 && stacktop[0] != 1) {
                  throw ScriptException(ScriptError.SCRIPT_ERR_MINIMALIF.mnemonic + "Argument for OpCodes.OP_IF/NOT_IF must be 0x01 or empty");
                }
              }

              fValue = castToBool(stacktop);
              if (opcode == OpCodes.OP_NOTIF) {
                fValue = !fValue;
              }
              stack.pollLast(); //pop top value off stack
            }
            ifStack.add(fValue);
            elseStack.add(false);
            continue;
          case OpCodes.OP_ELSE:
          //only one ELSE is allowed in IF after genesis
            if (ifStack.isEmpty() || (!elseStack.isEmpty() && elseStack.getLast() && verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)))
              throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OpCodes.OP_ELSE without OpCodes.OP_IF/NOTIF");
            ifStack.add(!ifStack.pollLast());
            elseStack.set(elseStack.size() - 1, true);
            continue;
          case OpCodes.OP_ENDIF:
            if (ifStack.isEmpty())
              throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OpCodes.OP_ENDIF without OpCodes.OP_IF/NOTIF");
            ifStack.pollLast();
            elseStack.pollLast();
            continue;

        // OpCodes.OP_0 is no opcode
          case OpCodes.OP_1NEGATE:
            stack.add(encodeMPI(BigInt.ONE.negate(), false).reversed);
            break;
          case OpCodes.OP_1:
          case OpCodes.OP_2:
          case OpCodes.OP_3:
          case OpCodes.OP_4:
          case OpCodes.OP_5:
          case OpCodes.OP_6:
          case OpCodes.OP_7:
          case OpCodes.OP_8:
          case OpCodes.OP_9:
          case OpCodes.OP_10:
          case OpCodes.OP_11:
          case OpCodes.OP_12:
          case OpCodes.OP_13:
          case OpCodes.OP_14:
          case OpCodes.OP_15:
          case OpCodes.OP_16:
            stack.add(encodeMPI(BigInt.valueOf(Script.decodeFromOpN(opcode)), false).reversed);
            break;
          case OpCodes.OP_NOP:
            break;
          case OpCodes.OP_VERIFY:
            if (stack.size() < 1)
              throw ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION.mnemonic + "-Attempted OpCodes.OP_VERIFY on an empty stack");
            if (!castToBool(stack.pollLast()))
              throw ScriptException(ScriptError.SCRIPT_ERR_VERIFY.mnemonic + "-OpCodes.OP_VERIFY failed");
            break;
          case OpCodes.OP_RETURN:
            if (verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)) {
              if (ifStack.isEmpty()) {
                // Terminate the execution as successful. The remainder of the script does not affect the validity (even in
                // presence of unbalanced IFs, invalid opcodes etc)
                return;
              }
              nonTopLevelReturnAfterGenesis = true;
            } else {
              // Pre-Genesis OpCodes.OP_RETURN marks script as invalid
              throw ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN.mnemonic + "Script called OpCodes.OP_RETURN");
            }
            break;

          case OpCodes.OP_TOALTSTACK:
            if (stack.size() < 1)
              throw ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION.mnemonic + "Attempted OpCodes.OP_TOALTSTACK on an empty stack");
            altstack.add(stack.pollLast());
            break;
          case OpCodes.OP_FROMALTSTACK:
            if (altstack.size() < 1)
              throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "Attempted OpCodes.OP_FROMALTSTACK on an empty altstack");
            stack.add(altstack.pollLast());
            break;
          case OpCodes.OP_2DROP:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_2DROP on a stack with size < 2");
            stack.pollLast();
            stack.pollLast();
            break;
          case OpCodes.OP_2DUP:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_2DUP on a stack with size < 2");
            Iterator<Uint8List> it2DUP = stack.descendingIterator();
            Uint8List OP2DUPtmpChunk2 = it2DUP.next();
            stack.add(it2DUP.next());
            stack.add(OP2DUPtmpChunk2);
            break;
          case OpCodes.OP_3DUP:
            if (stack.size() < 3)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_3DUP on a stack with size < 3");
            Iterator<Uint8List> it3DUP = stack.descendingIterator();
            Uint8List OP3DUPtmpChunk3 = it3DUP.next();
            Uint8List OP3DUPtmpChunk2 = it3DUP.next();
            stack.add(it3DUP.next());
            stack.add(OP3DUPtmpChunk2);
            stack.add(OP3DUPtmpChunk3);
            break;
          case OpCodes.OP_2OVER:
            if (stack.size() < 4)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_2OVER on a stack with size < 4");
            Iterator<Uint8List> it2OVER = stack.descendingIterator();
            it2OVER.next();
            it2OVER.next();
            Uint8List OP2OVERtmpChunk2 = it2OVER.next();
            stack.add(it2OVER.next());
            stack.add(OP2OVERtmpChunk2);
            break;
          case OpCodes.OP_2ROT:
            if (stack.size() < 6)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_2ROT on a stack with size < 6");
            Uint8List OP2ROTtmpChunk6 = stack.pollLast();
            Uint8List OP2ROTtmpChunk5 = stack.pollLast();
            Uint8List OP2ROTtmpChunk4 = stack.pollLast();
            Uint8List OP2ROTtmpChunk3 = stack.pollLast();
            Uint8List OP2ROTtmpChunk2 = stack.pollLast();
            Uint8List OP2ROTtmpChunk1 = stack.pollLast();
            stack.add(OP2ROTtmpChunk3);
            stack.add(OP2ROTtmpChunk4);
            stack.add(OP2ROTtmpChunk5);
            stack.add(OP2ROTtmpChunk6);
            stack.add(OP2ROTtmpChunk1);
            stack.add(OP2ROTtmpChunk2);
            break;
          case OpCodes.OP_2SWAP:
            if (stack.size() < 4)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_2SWAP on a stack with size < 4");
            Uint8List OP2SWAPtmpChunk4 = stack.pollLast();
            Uint8List OP2SWAPtmpChunk3 = stack.pollLast();
            Uint8List OP2SWAPtmpChunk2 = stack.pollLast();
            Uint8List OP2SWAPtmpChunk1 = stack.pollLast();
            stack.add(OP2SWAPtmpChunk3);
            stack.add(OP2SWAPtmpChunk4);
            stack.add(OP2SWAPtmpChunk1);
            stack.add(OP2SWAPtmpChunk2);
            break;
          case OpCodes.OP_IFDUP:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_IFDUP on an empty stack");
            if (castToBool(stack.getLast()))
              stack.add(stack.getLast());
            break;
          case OpCodes.OP_DEPTH:
            stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInt.valueOf(stack.size()), false)));
            break;
          case OpCodes.OP_DROP:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_DROP on an empty stack");
            stack.pollLast();
            break;
          case OpCodes.OP_DUP:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_DUP on an empty stack");
            stack.add(stack.getLast());
            break;
          case OpCodes.OP_NIP:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_NIP on a stack with size < 2");
            Uint8List OPNIPtmpChunk = stack.pollLast();
            stack.pollLast();
            stack.add(OPNIPtmpChunk);
            break;
          case OpCodes.OP_OVER:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_OVER on a stack with size < 2");
            Iterator<Uint8List> itOVER = stack.descendingIterator();
            itOVER.next();
            stack.add(itOVER.next());
            break;
          case OpCodes.OP_PICK:
          case OpCodes.OP_ROLL:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_PICK/OpCodes.OP_ROLL on an empty stack");
            int val = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA)).intValue();
            if (val < 0 || val >= stack.size())
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "OpCodes.OP_PICK/OpCodes.OP_ROLL attempted to get data deeper than stack size");
            Iterator<Uint8List> itPICK = stack.descendingIterator();
            for (int i = 0; i < val; i++)
              itPICK.next();
            Uint8List OPROLLtmpChunk = itPICK.next();
            if (opcode == OpCodes.OP_ROLL)
              itPICK.remove();
            stack.add(OPROLLtmpChunk);
            break;
          case OpCodes.OP_ROT:
            if (stack.size() < 3)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_ROT on a stack with size < 3");
            Uint8List OPROTtmpChunk3 = stack.pollLast();
            Uint8List OPROTtmpChunk2 = stack.pollLast();
            Uint8List OPROTtmpChunk1 = stack.pollLast();
            stack.add(OPROTtmpChunk2);
            stack.add(OPROTtmpChunk3);
            stack.add(OPROTtmpChunk1);
            break;
          case OpCodes.OP_SWAP:
          case OpCodes.OP_TUCK:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_SWAP on a stack with size < 2");
            Uint8List OPSWAPtmpChunk2 = stack.pollLast();
            Uint8List OPSWAPtmpChunk1 = stack.pollLast();
            stack.add(OPSWAPtmpChunk2);
            stack.add(OPSWAPtmpChunk1);
            if (opcode == OpCodes.OP_TUCK)
              stack.add(OPSWAPtmpChunk2);
            break;


          case OpCodes.OP_CAT:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");
            Uint8List catBytes2 = stack.pollLast();
            Uint8List catBytes1 = stack.pollLast();

            int len = catBytes1.length + catBytes2.length;
            if (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && len > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
              throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Push value size limit exceeded.");

            Uint8List catOut = new byte[len];
            System.arraycopy(catBytes1, 0, catOut, 0, catBytes1.length);
            System.arraycopy(catBytes2, 0, catOut, catBytes1.length, catBytes2.length);
            stack.addLast(catOut);

            break;

          case OpCodes.OP_NUM2BIN:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

            int numSize = castToBigInt(stack.pollLast(), maxScriptNumLength, enforceMinimal).intValue();

            if (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && numSize > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
              throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Push value size limit exceeded.");

            Uint8List rawNumBytes = stack.pollLast();

            // Try to see if we can fit that number in the number of
            // byte requested.
            Uint8List minimalNumBytes = Utils.minimallyEncodeLE(rawNumBytes);
            if (minimalNumBytes.length > numSize) {
              //we can't
              throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "The requested encoding is impossible to satisfy.");
            }

            if (minimalNumBytes.length == numSize) {
              //already the right size so just push it to stack
              stack.addLast(minimalNumBytes);
            } else if (numSize == 0) {
              stack.addLast(Utils.EMPTY_BYTE_ARRAY);
            } else {
              int signBit = 0x00;
              if (minimalNumBytes.length > 0) {
                signBit = minimalNumBytes[minimalNumBytes.length - 1] & 0x80;
                minimalNumBytes[minimalNumBytes.length - 1] &= 0x7f;
              }
              int minimalBytesToCopy = minimalNumBytes.length > numSize ? numSize : minimalNumBytes.length;
              Uint8List expandedNumBytes = new byte[numSize]; //initialized to all zeroes
              System.arraycopy(minimalNumBytes, 0, expandedNumBytes, 0, minimalBytesToCopy);
              expandedNumBytes[expandedNumBytes.length - 1] = (byte) signBit;
              stack.addLast(expandedNumBytes);
            }
            break;

          case OpCodes.OP_SPLIT:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

            BigInt biSplitPos = castToBigInt(stack.pollLast(), maxScriptNumLength, enforceMinimal);

            //sanity check in case we aren't enforcing minimal number encoding
            //we will check that the biSplitPos value can be safely held in an int
            //before we cast it as BigInt will behave similar to casting if the value
            //is greater than the target type can hold.
            BigInt biMaxInt = BigInt.valueOf((int) Integer.MAX_VALUE);
            if (biSplitPos.compareTo(biMaxInt) >= 0)
              throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid OpCodes.OP_SPLIT range.");

            int splitPos = biSplitPos.intValue();
            Uint8List splitBytes = stack.pollLast();

            if (splitPos > splitBytes.length || splitPos < 0)
              throw new ScriptException(ScriptError.SCRIPT_ERR_SPLIT_RANGE, "Invalid OpCodes.OP_SPLIT range.");

            Uint8List splitOut1 = new byte[splitPos];
            Uint8List splitOut2 = new byte[splitBytes.length - splitPos];

            System.arraycopy(splitBytes, 0, splitOut1, 0, splitPos);
            System.arraycopy(splitBytes, splitPos, splitOut2, 0, splitOut2.length);

            stack.addLast(splitOut1);
            stack.addLast(splitOut2);
            break;

          case OpCodes.OP_BIN2NUM:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");

            Uint8List binBytes = stack.pollLast();
            Uint8List numBytes = Utils.minimallyEncodeLE(binBytes);

            if (!Utils.checkMinimallyEncodedLE(numBytes, maxScriptNumLength))
              throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "Given operand is not a number within the valid range [-2^31...2^31]");

            stack.addLast(numBytes);

            break;
          case OpCodes.OP_SIZE:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_SIZE on an empty stack");
            stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInt.valueOf(stack
                .getLast()
                .length), false)));
            break;

          case OpCodes.OP_LSHIFT:
          case OpCodes.OP_RSHIFT:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Too few items on stack for SHIFT Op");

            Uint8List shiftCountBuf = stack.getLast();
            Uint8List valueToShiftBuf = stack.get(stack.size() - 2);

            if (valueToShiftBuf.length == 0) {
              stack.pop();
            } else {
              final BigInt shiftCount = castToBigInt(shiftCountBuf, 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

              int n = shiftCount.intValue();
              if (n < 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_NUMBER_RANGE, "Can't shift negative number of bits (n < 0)");

              stack.pop();
              stack.pop();

              //using the Bytes lib. In-place byte-ops.
              Bytes shifted = Bytes.wrap(valueToShiftBuf, ByteOrder.BIG_ENDIAN);

              if (opcode == ScriptOpCodes.OpCodes.OP_LSHIFT) {
                //Dart BigInt automagically right-pads the shifted bits
                shifted = shifted.leftShift(n);
              }
              if (opcode == ScriptOpCodes.OpCodes.OP_RSHIFT) {
                shifted = shifted.rightShift(n);
              }

              if (n > 0) {
                //shift occured
                stack.push(shifted.array());
              } else {
                //no shift, just push original value back onto stack
                stack.push(valueToShiftBuf);
              }
            }
            break;
          case OpCodes.OP_INVERT:
            {
              if (stack.size() < 1) {
                throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "No elements left on stack.");
              }
              Uint8List vch1 = stack.pollLast();
              // To avoid allocating, we modify vch1 in place
              for (int i = 0; i < vch1.length; i++) {
                vch1[i] = (byte)(~vch1[i] & 0xFF);
              }
              stack.push(vch1);

              break;
            }
          case OpCodes.OP_AND:
          case OpCodes.OP_OR:
          case OpCodes.OP_XOR:
          // (x1 x2 - out)
            if (stack.size() < 2) {
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Invalid stack operation.");
            }

            //valtype &vch2 = stacktop(-1);
            //valtype &vch1 = stacktop(-2);
            Uint8List vch2 = stack.pollLast();
            Uint8List vch1 = stack.pollLast();

            // Inputs must be the same size
            if (vch1.length != vch2.length) {
              throw new ScriptException(ScriptError.SCRIPT_ERR_OPERAND_SIZE, "Invalid operand size.");
            }

            // To avoid allocating, we modify vch1 in place.
            switch (opcode) {
              case OpCodes.OP_AND:
                for (int i = 0; i < vch1.length; i++) {
                  vch1[i] &= vch2[i];
                }
                break;
              case OpCodes.OP_OR:
                for (int i = 0; i < vch1.length; i++) {
                  vch1[i] |= vch2[i];
                }
                break;
              case OpCodes.OP_XOR:
                for (int i = 0; i < vch1.length; i++) {
                  vch1[i] ^= vch2[i];
                }
                break;
              default:
                break;
            }

            // And pop vch2.
            //popstack(stack);

            //put vch1 back on stack
            stack.addLast(vch1);

            break;

          case OpCodes.OP_EQUAL:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_EQUAL on a stack with size < 2");
            stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new Uint8List {1} : new Uint8List {});
            break;
          case OpCodes.OP_EQUALVERIFY:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_EQUALVERIFY on a stack with size < 2");
            if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
              throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "OpCodes.OP_EQUALVERIFY: non-equal data");
            break;
          case OpCodes.OP_1ADD:
          case OpCodes.OP_1SUB:
          case OpCodes.OP_NEGATE:
          case OpCodes.OP_ABS:
          case OpCodes.OP_NOT:
          case OpCodes.OP_0NOTEQUAL:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on an empty stack");
            BigInt numericOPnum = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));

            switch (opcode) {
              case OpCodes.OP_1ADD:
                numericOPnum = numericOPnum.add(BigInt.ONE);
                break;
              case OpCodes.OP_1SUB:
                numericOPnum = numericOPnum.subtract(BigInt.ONE);
                break;
              case OpCodes.OP_NEGATE:
                numericOPnum = numericOPnum.negate();
                break;
              case OpCodes.OP_ABS:
                if (numericOPnum.signum() < 0)
                  numericOPnum = numericOPnum.negate();
                break;
              case OpCodes.OP_NOT:
                if (numericOPnum.equals(BigInt.ZERO))
                  numericOPnum = BigInt.ONE;
                else
                  numericOPnum = BigInt.ZERO;
                break;
              case OpCodes.OP_0NOTEQUAL:
                if (numericOPnum.equals(BigInt.ZERO))
                  numericOPnum = BigInt.ZERO;
                else
                  numericOPnum = BigInt.ONE;
                break;
              default:
                throw new AssertionError("Unreachable");
            }

            stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
            break;
          case OpCodes.OP_ADD:
          case OpCodes.OP_SUB:
          case OpCodes.OP_DIV:
          case OpCodes.OP_MUL:
          case OpCodes.OP_MOD:
          case OpCodes.OP_BOOLAND:
          case OpCodes.OP_BOOLOR:
          case OpCodes.OP_NUMEQUAL:
          case OpCodes.OP_NUMNOTEQUAL:
          case OpCodes.OP_LESSTHAN:
          case OpCodes.OP_GREATERTHAN:
          case OpCodes.OP_LESSTHANOREQUAL:
          case OpCodes.OP_GREATERTHANOREQUAL:
          case OpCodes.OP_MIN:
          case OpCodes.OP_MAX:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on a stack with size < 2");
            BigInt numericOPnum2 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));
            BigInt numericOPnum1 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));

            BigInt numericOPresult;
            switch (opcode) {
              case OpCodes.OP_ADD:
                numericOPresult = numericOPnum1.add(numericOPnum2);
                break;
              case OpCodes.OP_SUB:
                numericOPresult = numericOPnum1.subtract(numericOPnum2);
                break;

              case OpCodes.OP_MUL:
                numericOPresult = numericOPnum1.multiply(numericOPnum2);
                break;

              case OpCodes.OP_DIV:
                if (numericOPnum2.intValue() == 0)
                  throw new ScriptException(ScriptError.SCRIPT_ERR_DIV_BY_ZERO, "Division by zero error");
                numericOPresult = numericOPnum1.divide(numericOPnum2);
                break;

              case OpCodes.OP_MOD:
                if (numericOPnum2.intValue() == 0)
                  throw new ScriptException(ScriptError.SCRIPT_ERR_MOD_BY_ZERO, "Modulo by zero error");

                /**
                 * BigInt doesn't behave the way we want for modulo operations.  Firstly it's
                 * always guaranteed to return a +ve result.  Secondly it will throw an exception
                 * if the 2nd operand is negative.
                 * Instead we will use the BigDecimal to perform modular arithmetic, then convert
                 * back to BigInt
                 */

                BigDecimal bd1 = new BigDecimal(numericOPnum1);
                BigDecimal bd2 = new BigDecimal(numericOPnum2);

                numericOPresult = bd1.remainder(bd2).toBigInt();

                break;

              case OpCodes.OP_BOOLAND:
                if (!numericOPnum1.equals(BigInt.ZERO) && !numericOPnum2.equals(BigInt.ZERO))
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_BOOLOR:
                if (!numericOPnum1.equals(BigInt.ZERO) || !numericOPnum2.equals(BigInt.ZERO))
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_NUMEQUAL:
                if (numericOPnum1.equals(numericOPnum2))
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_NUMNOTEQUAL:
                if (!numericOPnum1.equals(numericOPnum2))
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_LESSTHAN:
                if (numericOPnum1.compareTo(numericOPnum2) < 0)
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_GREATERTHAN:
                if (numericOPnum1.compareTo(numericOPnum2) > 0)
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_LESSTHANOREQUAL:
                if (numericOPnum1.compareTo(numericOPnum2) <= 0)
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_GREATERTHANOREQUAL:
                if (numericOPnum1.compareTo(numericOPnum2) >= 0)
                  numericOPresult = BigInt.ONE;
                else
                  numericOPresult = BigInt.ZERO;
                break;
              case OpCodes.OP_MIN:
                if (numericOPnum1.compareTo(numericOPnum2) < 0)
                  numericOPresult = numericOPnum1;
                else
                  numericOPresult = numericOPnum2;
                break;
              case OpCodes.OP_MAX:
                if (numericOPnum1.compareTo(numericOPnum2) > 0)
                  numericOPresult = numericOPnum1;
                else
                  numericOPresult = numericOPnum2;
                break;
              default:
                throw new RuntimeException("Opcode switched at runtime?");
            }

            stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
            break;
          case OpCodes.OP_NUMEQUALVERIFY:
            if (stack.size() < 2)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_NUMEQUALVERIFY on a stack with size < 2");
            BigInt OPNUMEQUALVERIFYnum2 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));
            BigInt OPNUMEQUALVERIFYnum1 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));

            if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
              throw new ScriptException(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY, "OpCodes.OP_NUMEQUALVERIFY failed");
            break;
          case OpCodes.OP_WITHIN:
            if (stack.size() < 3)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_WITHIN on a stack with size < 3");
            BigInt OPWITHINnum3 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));
            BigInt OPWITHINnum2 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));
            BigInt OPWITHINnum1 = castToBigInt(stack.pollLast(), maxScriptNumLength, verifyFlags.contains(VerifyFlag.MINIMALDATA));
            if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
              stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInt.ONE, false)));
            else
              stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInt.ZERO, false)));
            break;
          case OpCodes.OP_RIPEMD160:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_RIPEMD160 on an empty stack");
            RIPEMD160Digest digest = new RIPEMD160Digest();
            Uint8List dataToHash = stack.pollLast();
            digest.update(dataToHash, 0, dataToHash.length);
            Uint8List ripmemdHash = new byte[20];
            digest.doFinal(ripmemdHash, 0);
            stack.add(ripmemdHash);
            break;
          case OpCodes.OP_SHA1:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_SHA1 on an empty stack");
            try {
              stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
            } on NoSuchAlgorithmException catch (e) {
              throw new RuntimeException(e); // Cannot happen.
            }
            break;
          case OpCodes.OP_SHA256:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_SHA256 on an empty stack");
            stack.add(Sha256Hash.hash(stack.pollLast()));
            break;
          case OpCodes.OP_HASH160:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_HASH160 on an empty stack");
            stack.add(Utils.sha256hash160(stack.pollLast()));
            break;
          case OpCodes.OP_HASH256:
            if (stack.size() < 1)
              throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_SHA256 on an empty stack");
            stack.add(Sha256Hash.hashTwice(stack.pollLast()));
            break;
          case OpCodes.OP_CODESEPARATOR:
            lastCodeSepLocation = nextLocationInScript;
            break;
          case OpCodes.OP_CHECKSIG:
          case OpCodes.OP_CHECKSIGVERIFY:
            if (txContainingThis == null)
              throw new IllegalStateException("Script attempted signature check but no tx was provided");

            try {
              executeCheckSig(
                  txContainingThis,
                  (int) index, script, stack, lastCodeSepLocation, opcode, value, verifyFlags);
            } on SignatureEncodingException catch (ex) {
              stack.add(new Uint8List {}); //push false onto stack
              throw ScriptException(ex.getErr() + ex.getMessage());
            } catch (ex) {
              stack.add(new Uint8List {}); //push false onto stack
              throw ScriptException(ex.getErr(), ex.getMessage());
            }

            break;

          case OpCodes.OP_CHECKMULTISIG:
          case OpCodes.OP_CHECKMULTISIGVERIFY:
            if (txContainingThis == null)
              throw new IllegalStateException("Script attempted signature check but no tx was provided");
            try {
              opCount = executeMultiSig(
                  txContainingThis,
                  (int) index, script, stack, opCount, lastCodeSepLocation, opcode, value, verifyFlags);
            } on SignatureEncodingException catch (ex) {
              stack.add(new Uint8List {}); //push false onto stack
              throw new ScriptException(ex.getErr(), ex.getMessage());
            } on PubKeyEncodingException catch (ex) {
              stack.add(new Uint8List {}); //push false onto stack
              throw new ScriptException(ex.getErr(), ex.getMessage());
            }
            break;

          case OpCodes.OP_CHECKLOCKTIMEVERIFY:
            if (!verifyFlags.contains(VerifyFlag.CHECKLOCKTIMEVERIFY) || verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)) {
              // not enabled; treat as a NOP2
              if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
              }
              break;
            }
            executeCheckLockTimeVerify(txContainingThis, (int) index, stack, verifyFlags);
            break;

          case OpCodes.OP_CHECKSEQUENCEVERIFY:
            if (!verifyFlags.contains(VerifyFlag.CHECKSEQUENCEVERIFY) || verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS)) {
              // not enabled; treat as a NOP3
              if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
              }
              break;
            }
            executeCheckSequenceVerify(txContainingThis, (int) index, stack, verifyFlags);
            break;
          case OpCodes.OP_NOP1:
          case OpCodes.OP_NOP4:
          case OpCodes.OP_NOP5:
          case OpCodes.OP_NOP6:
          case OpCodes.OP_NOP7:
          case OpCodes.OP_NOP8:
          case OpCodes.OP_NOP9:
          case OpCodes.OP_NOP10:
            if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
              throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
            }
            break;

          default:
            if (isInvalidBranchingOpcode(opcode) && verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && !shouldExecute) {
              break;
            }
            throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Script used a reserved or disabled opcode: " + opcode);
        }
      }

      if (stack.size() + altstack.size() > MAX_STACK_SIZE || stack.size() + altstack.size() < 0)
        throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "Stack size exceeded range");
    }

    if (!ifStack.isEmpty())
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "OpCodes.OP_IF/OpCodes.OP_NOTIF without OpCodes.OP_ENDIF");
  }

  static bool isInvalidBranchingOpcode(int opcode) {
    return opcode == OpCodes.OP_VERIF || opcode == OpCodes.OP_VERNOTIF;
  }


  // This is more or less a direct translation of the code in Bitcoin Core
  void executeCheckLockTimeVerify(Transaction txContainingThis, int index, LinkedList<Uint8List> stack, Set<VerifyFlag> verifyFlags) {
    if (stack.size() < 1)
      throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKLOCKTIMEVERIFY on a stack with size < 1");

    // Thus as a special case we tell CScriptNum to accept up
    // to 5-byte bignums to avoid year 2038 issue.
    final BigInt nLockTime = castToBigInt(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

    if (nLockTime.compareTo(BigInt.ZERO) < 0)
      throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");

    // There are two kinds of nLockTime: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nLockTime <
    // LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nLockTime being tested is the same as the nLockTime in the
    // transaction.
    if (!(((txContainingThis.getLockTime() < Transaction.LOCKTIME_THRESHOLD) &&
        (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) < 0) ||
        ((txContainingThis.getLockTime() >= Transaction.LOCKTIME_THRESHOLD) &&
            (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) >= 0))) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement type mismatch");
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nLockTime.compareTo(BigInt.valueOf(txContainingThis.getLockTime())) > 0)
      throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
    // nSequence to maxint. The transaction would be allowed into the
    // blockchain, making the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to prevent this condition.
    // Alternatively we could test all inputs, but testing just this input
    // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
    // execution.
    if (!txContainingThis.getInputs().get(index).isFinal())
      throw new ScriptException(
          ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction contains a final transaction input for a CHECKLOCKTIMEVERIFY script. ");
  }


  void correctlySpends(Script scriptSig, Script scriptPubKey, Transaction txn, int scriptSigIndex, Set<VerifyFlag> verifyFlags) {
    correctlySpends(scriptSig, scriptPubKey, txn, scriptSigIndex, verifyFlags, Coin.ZERO);
  }

  /**
   * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
   * TODO: Verify why I'd need to pass in scriptSig again if I already have it from the [txn] + [scriptSigIndex] parameter
   *
   * @param scriptSig the spending Script
   * @param scriptSigIndex The index in the provided txn of the scriptSig
   * @param txn The transaction in which the provided scriptSig resides.
   *            Accessing txn from another thread while this method runs results in undefined behavior.
   * @param scriptPubKey The connected scriptPubKey (in output ) containing the conditions needed to claim the value.
   * @param verifyFlags Each flag enables one validation rule.
   * @param satoshis Value of the input ? Needed for verification when ForkId sighash is used
   */
  void correctlySpends(Script scriptSig, Script scriptPubKey, Transaction txn, int scriptSigIndex, Set<VerifyFlag> verifyFlags, Coin satoshis) {
//     void correctlySpends(Transaction txn, int scriptSigIndex, Script scriptPubKey, Coin value, Set<VerifyFlag> verifyFlags) throws ScriptException {
// Clone the transaction because executing the script involves editing it, and if we die, we'll leave
// the tx half broken (also it's not so thread safe to work on it directly.

    if (verifyFlags.contains(VerifyFlag.SIGPUSHONLY) && !Script.isPushOnly(scriptSig)) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "No pushdata operations allowed in scriptSig");
    }

    Transaction transaction;
    try {
      transaction = new Transaction(ByteBuffer.wrap(txn.serialize()));
    } on ProtocolException catch (e) {
      throw new RuntimeException(e); // Should not happen unless we were given a totally broken transaction.
    } on IOException catch (e) {
      throw new RuntimeException(e); // Should not happen unless we were given a totally broken transaction.
    }

    if (verifyFlags.contains(VerifyFlag.P2SH) && verifyFlags.contains(VerifyFlag.STRICTENC)) {
      if (scriptSig
          .getProgram()
          .length > 10000 || scriptPubKey
          .getProgram()
          .length > 10000)
        throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Script larger than 10,000 bytes");
    }

    LinkedList<Uint8List> stack = new LinkedList<Uint8List>();
    LinkedList<Uint8List> p2shStack = null;

    executeScript(transaction, scriptSigIndex, scriptSig, stack, satoshis, verifyFlags);
    if (verifyFlags.contains(VerifyFlag.P2SH) && !(verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS))) {
      p2shStack = new LinkedList<Uint8List>(stack);
    }

    executeScript(transaction, scriptSigIndex, scriptPubKey, stack, satoshis, verifyFlags);

    if (stack.size() == 0)
      throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Stack empty at end of script execution.");

    if (!castToBool(stack.getLast()))
      throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Script resulted in a non-true stack: " + stack);

// P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
// program but it has "useless" form that if evaluated as a normal program always returns true.
// Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
// and that must be provided by the input. The goal of this bizarre arrangement is twofold:
//
// (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
//     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
//     un-wieldy to copy/paste.
// (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
//     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
//     overall scalability and performance.

// TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
    if (verifyFlags.contains(VerifyFlag.P2SH)
        && ScriptPattern.isP2SH(scriptPubKey)
        && !(verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS))) {
      for (ScriptChunk chunk : scriptSig.getChunks())
    if (chunk.isOpCode() && chunk.opcode > OpCodes.OP_16)
    throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "Attempted to spend a P2SH scriptPubKey with a script that contained script ops");

    stack = new LinkedList<>(p2shStack); //restore stack
// stack cannot be empty here, because if it was the P2SH  HASH <> EQUAL
// scriptPubKey would be evaluated with an empty stack and the
// EvalScript above would return false.
    assert(!stack.isEmpty());

    Uint8List scriptPubKeyBytes = stack.pollLast();
    Script scriptPubKeyP2SH = new Script(scriptPubKeyBytes);

    executeScript(transaction, scriptSigIndex, scriptPubKeyP2SH, stack, satoshis, verifyFlags);

    if (stack.isEmpty())
    throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "P2SH stack empty at end of script execution.");

    if (!castToBool(stack.getLast()))
    throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "P2SH script execution resulted in a non-true stack");
    }

// The CLEANSTACK check is only performed after potential P2SH evaluation,
// as the non-P2SH evaluation of a P2SH script will obviously not result in
// a clean stack (the P2SH inputs remain). The same holds for witness
// evaluation.
    if (verifyFlags.contains(VerifyFlag.CLEANSTACK)){
// Disallow CLEANSTACK without P2SH, as otherwise a switch
// CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
// softfork (and P2SH should be one).
    assert(verifyFlags.contains(VerifyFlag.P2SH));
    if (stack.size() != 1){
    throw new ScriptException(ScriptError.SCRIPT_ERR_CLEANSTACK, "Cleanstack is disallowed without P2SH");
    }
    }
  }


  static void executeCheckSig(Transaction txContainingThis, int index, Script script, LinkedList<Uint8List> stack,
      int lastCodeSepLocation, int opcode, Coin value,
      Set<VerifyFlag> verifyFlags) {
    final bool requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
        || verifyFlags.contains(VerifyFlag.LOW_S);

    if (stack.size() < 2)
      throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKSIG(VERIFY) on a stack with size < 2");
    Uint8List pubKey = stack.pollLast();
    Uint8List sigBytes = stack.pollLast();

    Uint8List prog = script.getProgram();
    Uint8List connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

    UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sigBytes.length + 1);
    try {
      writeBytes(outStream, sigBytes);
    } on IOException catch (e) {
      throw new RuntimeException(e); // Cannot happen
    }
    connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());

// TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
    bool sigValid = false;


    checkSignatureEncoding(sigBytes, verifyFlags);
    checkPubKeyEncoding(pubKey, verifyFlags);

//default to 1 in case of empty Sigs
    int sigHashType = SighashType.UNSET.value;

    if (sigBytes.length > 0) {
      sigHashType = sigBytes[sigBytes.length - 1] & 0xFF;
    }

    try {
      if (TransactionSignature.hasForkId(sigBytes)) {
        if (!verifyFlags.contains(VerifyFlag.SIGHASH_FORKID)) {
          throw new ScriptException(ScriptError.SCRIPT_ERR_ILLEGAL_FORKID, "ForkID is not enabled, yet the flag is set");
        }
      }

      TransactionSignature sig = TransactionSignature.fromTxFormat(sigBytes);
      Script subScript = new Script(connectedScript);

// TODO: Should check hash type is known
      SigHash sigHash = new SigHash();

      Uint8List hash = sigHash.createHash(txContainingThis, sig.sighashFlags, index, subScript, BigInt.valueOf(value.value));
      sigValid = ECKey.verify(hash, sig, pubKey);
    } on Exception catch (e1) {
// There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
// Because I can't verify there aren't more, we use a very generic Exception catch

// This RuntimeException occurs when signing as we run partial/invalid scripts to see if they need more
// signing work to be done inside LocalTransactionSigner.signInputs.
      if (!e1.getMessage().contains("Reached past end of ASN.1 stream"))
        log.warn("Signature checking failed!", e1);
    }

    if (!sigValid && verifyFlags.contains(VerifyFlag.NULLFAIL) && sigBytes.length > 0) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "Failed strict DER Signature coding. ");
    }

    if (opcode == OpCodes.OP_CHECKSIG)
      stack.add(sigValid ? new Uint8List {1} : new Uint8List {});
    else if (opcode == OpCodes.OP_CHECKSIGVERIFY)
      if (!sigValid)
        throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, " Script failed OpCodes.OP_CHECKSIGVERIFY ");
  }

  /**
   * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len
   * S> <S> <hashtype>, where R and S are not negative (their first byte has its
   * highest bit not set), and not excessively padded (do not start with a 0 byte,
   * unless an otherwise negative number follows, in which case a single 0 byte is
   * necessary and even required).
   *
   * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
   *
   * This function is consensus-critical since BIP66.
   */
  static bool isValidSignatureEncoding
      (Uint8List sigBytes) {
// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
// [sighash]
// * total-length: 1-byte length descriptor of everything that follows,
// excluding the sighash byte.
// * R-length: 1-byte length descriptor of the R value that follows.
// * R: arbitrary-length big-endian encoded R value. It must use the
// shortest possible encoding for a positive integers (which means no null
// bytes at the start, except a single one when the next byte has its
// highest bit set).
// * S-length: 1-byte length descriptor of the S value that follows.
// * S: arbitrary-length big-endian encoded S value. The same rules apply.
// * sighash: 1-byte value indicating what data is hashed (not part of the
// DER signature)

// Minimum and maximum size constraints.
    if (sigBytes.length < 9) return false;
    if (sigBytes.length > 73) return false;

// A signature is of type 0x30 (compound).
    if (sigBytes[0] != 0x30) return false;

// Make sure the length covers the entire signature.
    if (sigBytes[1] != sigBytes.length - 3) return false;

// Extract the length of the R element.
    int lenR = sigBytes[3];

// Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sigBytes.length) return false;

// Extract the length of the S element.
    int lenS = sigBytes[5 + lenR];

// Verify that the length of the signature matches the sum of the length
// of the elements.
    if ((lenR + lenS + 7) != sigBytes.length) return false;

// Check whether the R element is an integer.
    if (sigBytes[2] != 0x02) return false;

// Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

// Negative numbers are not allowed for R.
    if ((sigBytes[4] & 0x80) != 0) return false; //FIXME: Check

// Null bytes at the start of R are not allowed, unless R would otherwise be
// interpreted as a negative number.
    if (lenR > 1 && (sigBytes[4] == 0x00) && ((sigBytes[5] & 0x80) == 0)) return false; //FIXME: Check

// Check whether the S element is an integer.
    if (sigBytes[lenR + 4] != 0x02) return false;

// Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

// Negative numbers are not allowed for S.
    if ((sigBytes[lenR + 6] & 0x80) != 0) return false;

// Null bytes at the start of S are not allowed, unless S would otherwise be
// interpreted as a negative number.
    if (lenS > 1 && (sigBytes[lenR + 6] == 0x00) && ((sigBytes[lenR + 7] & 0x80) == 0)) { //FIXME: Check
      return false;
    }

    return true;
  }


  ///Comparable to bitcoind's IsLowDERSignature. Returns true if the signature has a 'low' S-value.
  ///
  ///See also ECDSA signature algorithm which enforces
  ///See also BIP 62, 'low S values in signatures'
  static bool hasLowS(Uint8List sigBytes) {
    BigInt maxVal = new BigInt("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

    try {
      ECKey.ECDSASignature sig = ECKey.ECDSASignature.decodeFromDER(sigBytes);
      if ((sig.s.compareTo(BigInt.ONE) == -1) || (sig.s.compareTo(maxVal) == 1)) {
        return false;
      }
    }
    on SignatureDecodeException(ex) {
      return false;
    }

    return
      true;
  }

  static void checkIsLowDERSignature(Uint8List sigBytes) {
    if (!isValidSignatureEncoding(sigBytes)) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER.mnemonic + "Invalid signature encoding");
    }
    Uint8List sigCopy = Arrays.copyOf(sigBytes, sigBytes.length - 1); //drop Sighash flag
    if (!hasLowS(sigCopy)) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_HIGH_S, "Signature has high S. Low S expected.");
    }
  }

  static void checkSignatureEncoding(Uint8List sigBytes, Set<VerifyFlag> flags) {
// Empty signature. Not strictly DER encoded, but allowed to provide a
// compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sigBytes.length == 0) {
      return;
    }
    if ((flags.contains(VerifyFlag.DERSIG) | flags.contains(VerifyFlag.LOW_S) |
    flags.contains(VerifyFlag.STRICTENC)) &&
        !isValidSignatureEncoding(sigBytes)) {
      throw new SignatureEncodingException(ScriptError.SCRIPT_ERR_SIG_DER, "Invalid Signature Encoding");
    }
    if (flags.contains(VerifyFlag.LOW_S)) {
      checkIsLowDERSignature(sigBytes);
    }

    if (flags.contains(VerifyFlag.STRICTENC)) {
      int sigHashType = sigBytes[sigBytes.length - 1];


      bool usesForkId = (sigHashType & SighashType.FORKID.value) != 0;
      bool forkIdEnabled = flags.contains(VerifyFlag.SIGHASH_FORKID);
      if (!forkIdEnabled && usesForkId) {
        throw new SignatureEncodingException(ScriptError.SCRIPT_ERR_ILLEGAL_FORKID, "ForkID is not enabled, yet the flag is set");
      }
      if (forkIdEnabled && !usesForkId) {
        throw new SignatureEncodingException(ScriptError.SCRIPT_ERR_MUST_USE_FORKID, "ForkID flag is required");
      }

//check for valid sighashType
      if (!SighashType.hasValue(sigHashType)) {
        throw new SignatureEncodingException(ScriptError.SCRIPT_ERR_SIG_HASHTYPE, "Invalid Sighash type");
      }
    }
  }

  static bool isCanonicalPubkey(Uint8List pubkey) {
    if (pubkey.length < 33) {
//  Non-canonical  key: too short
      return false;
    }
    if (pubkey[0] == 0x04) {
      if (pubkey.length != 65) {
//  Non-canonical  key: invalid length for uncompressed key
        return false;
      }
    } else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
      if (pubkey.length != 33) {
//  Non-canonical  key: invalid length for compressed key
        return false;
      }
    } else {
//  Non-canonical  key: neither compressed nor uncompressed
      return false;
    }
    return true;
  }

  static bool isCompressedPubKey(Uint8List pubKey) {
    if (pubKey.length != 33) {
//  Non-canonical  key: invalid length for compressed key
      return false;
    }
    if (pubKey[0] != 0x02 && pubKey[0] != 0x03) {
//  Non-canonical  key: invalid prefix for compressed key
      return false;
    }
    return true;
  }


  static bool checkPubKeyEncoding(Uint8List pubKey, Set<VerifyFlag> flags) {
    if (flags.contains(VerifyFlag.STRICTENC) && !isCanonicalPubkey(pubKey)) {
      throw new PubKeyEncodingException(ScriptError.SCRIPT_ERR_PUBKEYTYPE, " key has invalid encoding");
    }

    if (flags.contains(VerifyFlag.COMPRESSED_PUBKEYTYPE) && !isCompressedPubKey(pubKey)) {
      throw new PubKeyEncodingException(ScriptError.SCRIPT_ERR_NONCOMPRESSED_PUBKEY, " key has invalid encoding");
    }

    return

      true;
  }


  static int executeMultiSig(Transaction txContainingThis, int index, Script script, LinkedList<Uint8List> stack,
      int opCount, int lastCodeSepLocation, int opcode, Coin value,
      Set<VerifyFlag> verifyFlags) {
    final bool requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
        || verifyFlags.contains(VerifyFlag.DERSIG)
        || verifyFlags.contains(VerifyFlag.LOW_S);
    final bool enforceMinimal = verifyFlags.contains(VerifyFlag.MINIMALDATA);
    final bool utxoAfterGenesis = verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS);

    if (
    stack.size() < 1)
      throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKMULTISIG(VERIFY) on a stack with size < 2");

    int pubKeyCount = castToBigInt(stack.pollLast(), getMaxScriptNumLength(utxoAfterGenesis), enforceMinimal).intValue();
    if (pubKeyCount < 0 || (!verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && pubKeyCount > 20)
        || (verifyFlags.contains(VerifyFlag.UTXO_AFTER_GENESIS) && pubKeyCount > Integer.MAX_VALUE))
      throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEY_COUNT, "OpCodes.OP_CHECKMULTISIG(VERIFY) with pubkey count out of range");
    opCount += pubKeyCount;

    if (!isValidMaxOpsPerScript(opCount, utxoAfterGenesis))
      throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKMULTISIGVERIFY, "Total op (count > 250 * 1024) during OpCodes.OP_CHECKMULTISIG(VERIFY)");

    if (stack.size() < pubKeyCount + 1)
      throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + 2");

//take all pubkeys off the stack
    LinkedList<Uint8List> pubkeys = new LinkedList<Uint8List>();
    for (int i = 0; i < pubKeyCount; i++) {
      Uint8List pubKey = stack.pollLast();
      pubkeys.add(pubKey);
    }

    int sigCount = castToBigInt(stack.pollLast(), getMaxScriptNumLength(utxoAfterGenesis), enforceMinimal).intValue();
    if (sigCount < 0 || sigCount > pubKeyCount)
      throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_COUNT, "OpCodes.OP_CHECKMULTISIG(VERIFY) with sig count out of range");
    if (stack.size() < sigCount + 1)
      throw new ScriptException(
          SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + num_of_signatures + 3");

//take all signatures off the stack
    LinkedList<Uint8List> sigs = new LinkedList<Uint8List>();
    for (int i = 0; i < sigCount; i++) {
      Uint8List sig = stack.pollLast();
      sigs.add(sig);
    }

    Uint8List prog = script.getProgram();
    Uint8List connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

    for (Uint8List sig : sigs) {
      UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sig.length + 1);
      try {
        writeBytes(outStream, sig);
      } on IOException catch (e) {
        throw RuntimeException(e); // Cannot happen
      }
      connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());
    }


// ikey2 is the position of last non-signature item in
// the stack. Top stack item = 1. With
// SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
// operation fails.
    int ikey2 = pubKeyCount + 2;

    bool valid = true;

    while (valid && sigs.size() > 0) {
      Uint8List pubKey = pubkeys.pollFirst();
      Uint8List sigBytes = sigs.getFirst();
// We could reasonably move this out of the loop, but because signature verification is significantly
// more expensive than hashing, its not a big deal.

      checkSignatureEncoding(sigBytes, verifyFlags);
      checkPubKeyEncoding(pubKey, verifyFlags);


//default to 1 in case of empty Sigs
      int sigHashType = SighashType.UNSET.value;

      if (sigBytes.length > 0) {
        sigHashType = sigBytes[sigBytes.length - 1];
      }


      try {
        TransactionSignature sig = TransactionSignature.fromTxFormat(sigBytes);
        Script subScript = new Script(connectedScript);

// TODO: Should check hash type is known
        Sighash sigHash = new Sighash();

        int sighashMode = sig.sighashFlags;
        if (sig.useForkId()) {
          sighashMode = sig.sighashFlags | SighashType.FORKID.value;
        }

        Uint8List hash = sigHash.createHash(txContainingThis, sighashMode, index, subScript, BigInt.valueOf(value.value)); //FIXME: Use Coin instead ?
        if (ECKey.verify(hash, sigBytes, pubKey)) {
          sigs.pollFirst(); //pop a successfully validated sig
        }

        pubKeyCount--;
      } on Exception catch (e) {
// There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
// Because I can't verify there aren't more, we use a very generic Exception catch
      }

// If there are more signatures left than keys left,
// then too many signatures have failed. Exit early,
// without checking any further signatures.
      if (sigs.size() > pubkeys.size()) {
        valid = false;
      }
    }

// If the operation failed, we require that all
// signatures must be empty vector
    while (sigs.size() > 0) {
      if (!valid && verifyFlags.contains(VerifyFlag.NULLFAIL) && sigs
          .getLast()
          .length > 0) {
        throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "Failed strict DER Signature coding. ");
      }

      sigs.pollLast();
    }

// A bug causes CHECKMULTISIG to consume one extra
// argument whose contents were not checked in any way.
//
// Unfortunately this is a potential source of
// mutability, so optionally verify it is exactly equal
// to zero prior to removing it from the stack.
    if (stack.size() < 1) {
      throw new ScriptException(SCRIPT_ERR_INVALID_STACK_OPERATION, "No dummy element left on stack to compensate for Core bug");
    }

//pop the dummy element (core bug argument)
    Uint8List nullDummy = stack.pollLast();
    if (verifyFlags.contains(VerifyFlag.NULLDUMMY) && nullDummy.length > 0)
      throw new ScriptException(
          ScriptError.SCRIPT_ERR_SIG_NULLDUMMY, "OpCodes.OP_CHECKMULTISIG(VERIFY) with non-null nulldummy: " + Arrays.toString(nullDummy));


    if (opcode == OpCodes.OP_CHECKMULTISIG) {
      stack.add(valid ? new Uint8List {1} : new Uint8List {});
    } else if (opcode == OpCodes.OP_CHECKMULTISIGVERIFY) {
      if (!valid)
        throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKMULTISIGVERIFY, "Script failed OpCodes.OP_CHECKMULTISIGVERIFY");
    }
    return
      opCount;
  }


  static void executeCheckSequenceVerify(Transaction txContainingThis, int index, LinkedList<Uint8List> stack, Set<VerifyFlag> verifyFlags) {
    if (stack.size() < 1)
      throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OpCodes.OP_CHECKSEQUENCEVERIFY on a stack with size < 1");

// Note that elsewhere numeric opcodes are limited to
// operands in the range -2**31+1 to 2**31-1, however it is
// legal for opcodes to produce results exceeding that
// range. This limitation is implemented by CScriptNum's
// default 4-byte limit.
//
// Thus as a special case we tell CScriptNum to accept up
// to 5-byte bignums, which are good until 2**39-1, well
// beyond the 2**32-1 limit of the nSequence field itself.
    final int nSequence = castToBigInt(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA)).intValue();

// In the rare event that the argument may be < 0 due to
// some arithmetic being done first, you can always use
// 0 MAX CHECKSEQUENCEVERIFY.
    if (nSequence < 0)
      throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative sequence");

// To provide for future soft-fork extensibility, if the
// operand has the disabled lock-time flag set,
// CHECKSEQUENCEVERIFY behaves as a NOP.
    if ((nSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
      return;

// Compare the specified sequence number with the input.
    checkSequence(nSequence, txContainingThis, index);
  }

  void checkSequence(int nSequence, Transaction txContainingThis, int index) {
// Relative lock times are supported by comparing the passed
// in operand to the sequence number of the input.
    int txToSequence = txContainingThis.getInputs().get(index).getSequenceNumber();

// Fail if the transaction's version number is not set high
// enough to trigger BIP 68 rules.
    if (
    txContainingThis.getVersion() < 2)
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction version is < 2");

// Sequence numbers with their most significant bit set are not
// consensus constrained. Testing that the transaction's sequence
// number do not have this bit set prevents using this property
// to get around a CHECKSEQUENCEVERIFY check.
    if ((txToSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Sequence disable flag is set");

// Mask off any bits that do not have consensus-enforced meaning
// before doing the integer comparisons
    int nLockTimeMask = TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG | TransactionInput.SEQUENCE_LOCKTIME_MASK;
    int txToSequenceMasked = txToSequence & nLockTimeMask;
    int nSequenceMasked = nSequence & nLockTimeMask;

// There are two kinds of nSequence: lock-by-blockheight
// and lock-by-blocktime, distinguished by whether
// nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
//
// We want to compare apples to apples, so fail the script
// unless the type of nSequenceMasked being tested is the same as
// the nSequenceMasked in the transaction.
    if (!((txToSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG))) {
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement type mismatch");
    }

// Now that we know we're comparing apples-to-apples, the
// comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
      throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement not satisfied");
  }

  static int getMaxScriptNumLength(bool isGenesisEnabled) {
    if (!isGenesisEnabled) {
      return MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS;
    }

    return MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS; // use new limit after genesis
  }

  static int getMaxOpsPerScript(bool isGenesisEnabled) {
    if (!isGenesisEnabled) {
      return MAX_OPS_PER_SCRIPT_BEFORE_GENESIS; // no changes before genesis
    }

    return MAX_OPS_PER_SCRIPT_AFTER_GENESIS; // use new limit after genesis
  }

  static bool isValidMaxOpsPerScript(int nOpCount, bool isGenesisEnabled) {
    return (nOpCount <= getMaxOpsPerScript(isGenesisEnabled));
  }
}
