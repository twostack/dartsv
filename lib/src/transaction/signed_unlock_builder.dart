

import 'package:dartsv/src/signature.dart';

/// All unlocking scripts that will use OP_CHECKSIG or OP_CHECKMULTISIG operations
/// must implement this interface. Implementing this interface will signal to
/// the framework that the unlocking script (scriptSig) will participate in
/// the process of generating signatures for the [Transaction]'s Input Script.
///
/// This interface will *always* need to be implemented alongside the
/// [UnlockingScriptBuilder] interface.
///
/// After composing the [Transaction], when the developer calls the
/// Transaction.signInput() method, the framework will inject the resultant
/// signature into the [signatures] property of the
/// [SignedUnlockBuilder] instance. This will allow the developer to use these
/// signatures in generating the appropriate Input Script when the subclasses'
/// [UnlockingScriptBuilder.getScriptSig()] method is called by either the
/// framework, or explicitly by the developer themselves.
///
abstract class SignedUnlockBuilder {

  /// The [signatures] property defines a list of signatures injected by
  /// the framework whenever the Transaction.signInput() method is called.
  /// Multiple sequential calls to Transaction.signInput() will cause
  /// additional signatures to be added to this list.
  ///
  List<SVSignature> get signatures;


  set signatures(List<SVSignature> value);
}
