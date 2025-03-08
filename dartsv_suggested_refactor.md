# DartSV Library Refactoring Suggestions

## Overview

After examining the current dartsv library implementation and our wallet requirements, we've identified several enhancements needed to support a script-centric wallet model that can handle various locking mechanisms beyond P2PKH addresses. The current library provides a solid foundation with its script handling capabilities, but requires extensions to fully support our wallet refactoring goals.

## Current Capabilities

The dartsv library currently provides:

1. **Core Script Classes**:
   - `SVScript`: Base class for all Bitcoin scripts
   - `ScriptBuilder`: Utility for building scripts programmatically
   - `ScriptPattern`: Limited identification of script types (P2SH)

2. **Script Builder Abstractions**:
   - `LockingScriptBuilder`: Abstract class for creating locking scripts (scriptPubKey)
   - `UnlockingScriptBuilder`: Abstract class for creating unlocking scripts (scriptSig)

3. **Custom Implementations**:
   - Various specialized script builders for different protocols (B, PP1, HODL, etc.)

## Required Enhancements

To support a script-centric wallet model, the following enhancements are needed:

### 1. Script Type Identification and Registry

Create a comprehensive system to identify and register different script types:

```dart
abstract class ScriptTemplate {
  String get name;
  bool matches(SVScript script);
  LockingScriptBuilder createBuilder(Map<String, dynamic> params);
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params);
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script);
  Map<String, dynamic> extractScriptInfo(SVScript script);
}

class ScriptTemplateRegistry {
  final Map<String, ScriptTemplate> _templates = {};
  
  void register(ScriptTemplate template) {
    _templates[template.name] = template;
  }
  
  ScriptTemplate? getTemplate(String name) {
    return _templates[name];
  }
  
  String? identifyScriptType(SVScript script) {
    for (var entry in _templates.entries) {
      if (entry.value.matches(script)) {
        return entry.key;
      }
    }
    return null;
  }
  
  LockingScriptBuilder? createBuilder(String scriptType, Map<String, dynamic> params) {
    final template = _templates[scriptType];
    return template?.createBuilder(params);
  }
}
```

### 2. Enhanced Script Builders with Spendability Methods

Extend the `LockingScriptBuilder` class to include methods for determining spendability:

```dart
abstract class EnhancedLockingScriptBuilder extends LockingScriptBuilder {
  /// Determines if this script can be spent with the provided keys
  bool isSpendableWithKeys(List<SVPublicKey> availableKeys);
  
  /// Returns detailed information about the script
  Map<String, dynamic> getScriptInfo();
  
  /// Returns the type of script (P2PKH, P2MS, etc.)
  String getScriptType();
  
  /// Creates an appropriate unlocking script builder for this locking script
  UnlockingScriptBuilder createMatchingUnlockingBuilder(Map<String, dynamic> params);
}
```

### 3. Standard Script Templates Implementation

Implement standard script templates for common Bitcoin script types:

```dart
class P2PKHTemplate implements ScriptTemplate {
  @override
  String get name => 'P2PKH';
  
  @override
  bool matches(SVScript script) {
    // Implementation to identify P2PKH scripts
    // OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
  }
  
  @override
  LockingScriptBuilder createBuilder(Map<String, dynamic> params) {
    // Create P2PKH locking script builder
  }
  
  @override
  UnlockingScriptBuilder createUnlockingBuilder(Map<String, dynamic> params) {
    // Create P2PKH unlocking script builder
  }
  
  @override
  bool canBeSatisfiedBy(List<SVPublicKey> availableKeys, SVScript script) {
    // Extract pubKeyHash and check if any key matches
  }
  
  @override
  Map<String, dynamic> extractScriptInfo(SVScript script) {
    // Extract and return information about the script
  }
}

// Similar implementations for P2MS, OP_RETURN, etc.
```

### 4. Script Metadata and Analysis

Enhance `SVScript` with additional analysis capabilities:

```dart
extension SVScriptAnalysis on SVScript {
  /// Returns true if this script is a standard P2PKH script
  bool get isP2PKH => ScriptPattern.isP2PKH(this);
  
  /// Returns true if this script is a standard P2SH script
  bool get isP2SH => ScriptPattern.isP2SH(this);
  
  /// Returns true if this script is a standard P2MS (multisig) script
  bool get isP2MS => ScriptPattern.isP2MS(this);
  
  /// Returns true if this script is an OP_RETURN (data) script
  bool get isOpReturn => ScriptPattern.isOpReturn(this);
  
  /// Returns the addresses associated with this script, if any
  List<String> getAddresses(NetworkType networkType) {
    // Implementation to extract addresses from various script types
  }
  
  /// Returns the script type as a string
  String getScriptType() {
    // Implementation to determine script type
  }
}
```

### 5. Enhanced ScriptPattern Class

Expand the `ScriptPattern` class to identify more script types:

```dart
class ScriptPattern {
  // Existing methods...
  
  /// Returns true if the script is a standard P2MS (multi-signature) script
  static bool isP2MS(SVScript script) {
    // Implementation to identify multi-sig scripts
    // m <pubkey1> <pubkey2> ... <pubkeyn> n OP_CHECKMULTISIG
  }
  
  /// Returns true if the script is an OP_RETURN data script
  static bool isOpReturn(SVScript script) {
    // Implementation to identify OP_RETURN scripts
    // OP_RETURN <data>
  }
  
  /// Returns true if the script is a standard P2PKH script
  static bool isP2PKH(SVScript script) {
    // Implementation to identify P2PKH scripts
    // OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
  }
  
  /// Returns true if the script is a time-locked script
  static bool isTimeLocked(SVScript script) {
    // Implementation to identify time-locked scripts
    // <locktime> OP_CHECKLOCKTIMEVERIFY ...
  }
  
  // Additional methods for other script types...
}
```

### 6. Script Utility Functions

Add utility functions for working with scripts:

```dart
class ScriptUtils {
  /// Extracts public key hashes from a script
  static List<Uint8List> extractPubKeyHashes(SVScript script) {
    // Implementation
  }
  
  /// Extracts public keys from a script
  static List<SVPublicKey> extractPublicKeys(SVScript script) {
    // Implementation
  }
  
  /// Creates a P2PKH script from an address
  static SVScript createP2PKHScript(String address) {
    // Implementation
  }
  
  /// Creates a P2MS script from public keys and required signatures
  static SVScript createP2MSScript(List<SVPublicKey> publicKeys, int requiredSignatures) {
    // Implementation
  }
  
  /// Creates an OP_RETURN script from data
  static SVScript createOpReturnScript(Uint8List data) {
    // Implementation
  }
}
```

## Implementation Priorities

1. **Core Script Template System**:
   - Implement `ScriptTemplate` interface
   - Create `ScriptTemplateRegistry`
   - Implement standard templates (P2PKH, P2MS, OP_RETURN)

2. **Enhanced Script Analysis**:
   - Expand `ScriptPattern` with more script type identification
   - Add script metadata extraction methods
   - Implement spendability determination

3. **Script Builder Enhancements**:
   - Extend `LockingScriptBuilder` with spendability methods
   - Create matching unlocking script builders
   - Implement script info extraction

4. **Utility Functions**:
   - Add helper methods for common script operations
   - Implement script conversion utilities

## Benefits

1. **Flexibility**: Support for all BitcoinSV script types
2. **Extensibility**: Easy addition of new script templates
3. **Spendability**: Accurate determination of script spendability
4. **Integration**: Better integration with wallet functionality

## Conclusion

These enhancements to the dartsv library will provide a solid foundation for implementing a script-centric wallet model. By focusing on script capabilities rather than just addresses, we can support the full range of BitcoinSV's scripting capabilities while maintaining a clean and extensible architecture.

The suggested changes build upon the existing library structure, ensuring backward compatibility while adding the new functionality needed for our wallet refactoring.
