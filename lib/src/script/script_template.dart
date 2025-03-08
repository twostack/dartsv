import 'package:dartsv/dartsv.dart';
import 'package:dartsv/src/script/svscript.dart';
import 'package:dartsv/src/transaction/locking_script_builder.dart';
import 'package:dartsv/src/transaction/unlocking_script_builder.dart';

/// Base interface for all script templates
/// 
/// A script template defines a specific pattern of Bitcoin script and provides
/// methods to create, identify, and extract information from scripts of that pattern.
abstract class ScriptTemplate {
  /// The name of the script template (e.g., "P2PKH", "P2MS", "OP_RETURN")
  String get name;
  
  /// Determines if a script matches this template pattern
  bool matches(SVScript script);
  
  /// Creates a locking script builder for this template with the given parameters
  LockingScriptBuilder createBuilder(Map<String, dynamic> params);
  
  /// Creates an unlocking script builder for this template with the given parameters
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params);
  
  /// Determines if this script can be spent with the provided keys
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script);
  
  /// Extracts and returns information about the script
  Map<String, dynamic> extractScriptInfo(SVScript script);
}

/// Registry for script templates
/// 
/// This class maintains a registry of script templates and provides methods to
/// identify script types and create appropriate builders.
class ScriptTemplateRegistry {
  static final ScriptTemplateRegistry _instance = ScriptTemplateRegistry._internal();
  
  factory ScriptTemplateRegistry() {
    return _instance;
  }
  
  ScriptTemplateRegistry._internal();
  
  final Map<String, ScriptTemplate> _templates = {};
  
  /// Registers a script template with the registry
  void register(ScriptTemplate template) {
    _templates[template.name] = template;
  }
  
  /// Gets a script template by name
  ScriptTemplate? getTemplate(String name) {
    return _templates[name];
  }
  
  /// Identifies the type of a script
  /// 
  /// Returns the name of the matching template, or null if no match is found
  String? identifyScriptType(SVScript script) {
    for (var entry in _templates.entries) {
      if (entry.value.matches(script)) {
        return entry.key;
      }
    }
    return null;
  }
  
  /// Creates a locking script builder for the given script type and parameters
  LockingScriptBuilder? createBuilder(String scriptType, Map<String, dynamic> params) {
    final template = _templates[scriptType];
    return template?.createBuilder(params);
  }
  
  /// Creates an unlocking script builder for the given script type and parameters
  UnlockingScriptBuilder? createUnlockingBuilder(String scriptType, Map<String, dynamic> params) {
    final template = _templates[scriptType];
    return template?.createUnlockingBuilder(params);
  }
  
  /// Determines if a script can be spent with the provided keys
  bool canBeSatisfiedBy(SVScript script, List<SVPublicKey> availableKeys) {
    final scriptType = identifyScriptType(script);
    if (scriptType == null) return false;
    
    final template = _templates[scriptType];
    return template?.canBeSatisfiedBy(availableKeys, script) ?? false;
  }
  
  /// Extracts information from a script
  Map<String, dynamic>? extractScriptInfo(SVScript script) {
    final scriptType = identifyScriptType(script);
    if (scriptType == null) return null;
    
    final template = _templates[scriptType];
    return template?.extractScriptInfo(script);
  }
}
