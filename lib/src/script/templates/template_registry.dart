import 'package:dartsv/src/script/script_template.dart';
import 'package:dartsv/src/script/templates/p2pkh_template.dart';
import 'package:dartsv/src/script/templates/p2pk_template.dart';
import 'package:dartsv/src/script/templates/p2sh_template.dart';
import 'package:dartsv/src/script/templates/p2ms_template.dart';
import 'package:dartsv/src/script/templates/op_return_template.dart';
import 'package:dartsv/src/script/templates/author_identity_template.dart';
import 'package:dartsv/src/script/templates/b_protocol_template.dart';
import 'package:dartsv/src/script/templates/hodlocker_template.dart';

/// Initializes the script template registry with standard templates
class TemplateRegistry {
  /// Initialize the registry with standard templates
  static void initialize() {
    final registry = ScriptTemplateRegistry();

    // Register standard templates
    registry.register(P2PKHTemplate());
    registry.register(P2PKTemplate());
    registry.register(P2SHTemplate());
    registry.register(P2MSTemplate());
    registry.register(OpReturnTemplate());
    registry.register(AuthorIdentityTemplate());
    registry.register(BProtocolTemplate());
    registry.register(HODLockerTemplate());
  }
}
