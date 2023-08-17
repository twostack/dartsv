///
///
/// Flags are used to signal various expected behaviours to the Script Interpreter.
///
///
/// __Flags are taken from the bitcoind implementation__
///
/// ## SCRIPT_VERIFY_P2SH
/// Evaluate P2SH subscripts (softfork safe, BIP16).
///
/// ## SCRIPT_VERIFY_STRICTENC
/// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
/// Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
/// skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
///
/// ## SCRIPT_VERIFY_DERSIG
/// Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
///
/// ## SCRIPT_VERIFY_LOW_S
/// Pa non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
/// (softfork safe, BIP62 rule 5).
///
/// ## SCRIPT_VERIFY_NULLDUMMY
/// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
///
/// ## SCRIPT_VERIFY_SIGPUSHONLY
/// Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
///
/// ## SCRIPT_VERIFY_MINIMALDATA
/// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
/// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
/// any other push causes the script to fail (BIP62 rule 3).
/// In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
/// (softfork safe)
///
/// ## SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
/// Discourage use of NOPs reserved for upgrades (NOP1-10).
/// Provided so that nodes can avoid accepting or mining transactions
/// containing executed NOP's whose meaning may change after a soft-fork,
/// thus rendering the script invalid; with this flag set executing
/// discouraged NOPs fails the script. This verification flag will never be
/// a mandatory flag applied to scripts in a block. NOPs that are not
/// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
///
/// ## SCRIPT_VERIFY_CLEANSTACK
/// Require that only a single stack element remains after evaluation. This
/// changes the success criterion from "At least one stack element must
/// remain, and when interpreted as a boolean, it must be true" to "Exactly
/// one stack element must remain, and when interpreted as a boolean, it must
/// be true".
/// (softfork safe, BIP62 rule 6)
/// Note: CLEANSTACK should never be used without P2SH or WITNESS.
///
/// ## SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
/// Cstatic final LTV See BIP65 for details.
///
/// ## SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
/// support CHECKSEQUENCEVERIFY opcode
/// See BIP112 for details
///
/// ## SCRIPT_VERIFY_MINIMALIF
/// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
/// 0x01 or empty vector
///
/// ## SCRIPT_VERIFY_NULLFAIL
/// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
///
/// ## SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE
/// Public keys in scripts must be compressed
///
/// ## SCRIPT_ENABLE_SIGHASH_FORKID
/// Do we accept signature using SIGHASH_FORKID
///
/// ## SCRIPT_ENABLE_REPLAY_PROTECTION
/// Do we accept activate replay protection using a different fork id.
///
/// ## SCRIPT_ENABLE_MONOLITH_OPCODES
/// Enable new opcodes.
///
/// ## SCRIPT_ENABLE_MAGNETIC_OPCODES
/// Are the Magnetic upgrade opcodes enabled?
///
///
/// __Below flags apply in the context of BIP 68__
///
/// ## SEQUENCE_LOCKTIME_DISABLE_FLAG
///  If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time.
///
/// ## SEQUENCE_LOCKTIME_TYPE_FLAG
/// If CTxIn::nSequence encodes a relative lock-time and this flag is set,
/// the relative lock-time has units of 512 seconds, otherwise it specifies
/// blocks with a granularity of 1.
///
/// ## SEQUENCE_LOCKTIME_MASK
/// If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
/// extract that lock-time from the sequence field.
class ScriptFlags {

    /// bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    static final SCRIPT_VERIFY_NONE = 0;

    /// Evaluate P2SH subscripts (softfork safe, BIP16).
    static final SCRIPT_VERIFY_P2SH = (1 << 0);


    /// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    /// Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
    /// skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
    static final SCRIPT_VERIFY_STRICTENC = (1 << 1);

    /// Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    static final SCRIPT_VERIFY_DERSIG = (1 << 2);

    /// Pa non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    /// (softfork safe, BIP62 rule 5).
    static final SCRIPT_VERIFY_LOW_S = (1 << 3);

    /// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    static final SCRIPT_VERIFY_NULLDUMMY = (1 << 4);

    /// Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    static final SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5);

    /// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    /// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    /// any other push causes the script to fail (BIP62 rule 3).
    /// In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    /// (softfork safe)
    static final SCRIPT_VERIFY_MINIMALDATA = (1 << 6);

    /// Discourage use of NOPs reserved for upgrades (NOP1-10)
    ///
    /// Provided so that nodes can avoid accepting or mining transactions
    /// containing executed NOP's whose meaning may change after a soft-fork,
    /// thus rendering the script invalid; with this flag set executing
    /// discouraged NOPs fails the script. This verification flag will never be
    /// a mandatory flag applied to scripts in a block. NOPs that are not
    /// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    static final SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7);

    /// Require that only a single stack element remains after evaluation. This
    /// changes the success criterion from "At least one stack element must
    /// remain, and when interpreted as a boolean, it must be true" to "Exactly
    /// one stack element must remain, and when interpreted as a boolean, it must
    /// be true".
    /// (softfork safe, BIP62 rule 6)
    /// Note: CLEANSTACK should never be used without P2SH or WITNESS.
    static final SCRIPT_VERIFY_CLEANSTACK = (1 << 8);

    /// Cstatic final LTV See BIP65 for details.
    static final SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9);

    /// support CHECKSEQUENCEVERIFY opcode
    ///
    /// See BIP112 for details
    static final SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10);

    /// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
    /// 0x01 or empty vector
    ///
    static final SCRIPT_VERIFY_MINIMALIF = (1 << 13);

    /// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    ///
    static final SCRIPT_VERIFY_NULLFAIL = (1 << 14);

    /// Public keys in scripts must be compressed
    static final SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = (1 << 15);

    /// Do we accept signature using SIGHASH_FORKID
    ///
    static const SCRIPT_ENABLE_SIGHASH_FORKID = (1 << 16);

    /// Do we accept activate replay protection using a different fork id.
    ///
    static final SCRIPT_ENABLE_REPLAY_PROTECTION = (1 << 17);

    /// Enable new opcodes.
    ///
    static final SCRIPT_ENABLE_MONOLITH_OPCODES = (1 << 18);

    /// UTXO being used in this script was created *after* Genesis upgrade
    /// has been activated. This activates new rules (such as original meaning of OP_RETURN)
    /// This is per (input!) UTXO flag
    static final SCRIPT_UTXO_AFTER_GENESIS = (1 << 19);

    /// *Below flags apply in the context of BIP 68*
    ///
    /// If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time.

    static final SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);


    /// If CTxIn::nSequence encodes a relative lock-time and this flag is set,
    /// the relative lock-time has units of 512 seconds, otherwise it specifies
    /// blocks with a granularity of 1.

    static final SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    ///
    ///  If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
    ///  extract that lock-time from the sequence field.
    ///
    static final SEQUENCE_LOCKTIME_MASK = 0x0000ffff;


}
