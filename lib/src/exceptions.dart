
class AddressFormatException implements Exception {
    String cause;

    AddressFormatException(this.cause);
}

class BadChecksumException implements AddressFormatException{
    String cause;

    BadChecksumException(this.cause);
}

class BadParameterException implements Exception {
    String cause;

    BadParameterException(this.cause);
}


class InvalidPointException implements Exception {
    String cause;

    InvalidPointException(this.cause);
}


class InvalidNetworkException implements Exception {
    String cause;

    InvalidNetworkException(this.cause);
}

class InvalidKeyException implements Exception {
    String cause;

    InvalidKeyException(this.cause);
}

class IllegalArgumentException implements Exception{
    String cause;

    IllegalArgumentException(this.cause);
}


class DerivationException implements Exception{
    String cause;

    DerivationException(this.cause);
}


class InvalidPathException implements Exception{
    String cause;

    InvalidPathException(this.cause);
}

class UTXOException implements Exception {
    String cause;

    UTXOException(this.cause);
}

class TransactionAmountException implements Exception {
    String cause;

    TransactionAmountException(this.cause);

}

class ScriptException implements Exception {
    String cause;

    ScriptException(this.cause);

}

class SignatureException implements Exception {
    String cause;

    SignatureException(this.cause);
}


class TransactionFeeException implements Exception {
    String cause;

    TransactionFeeException(this.cause);
}

class InputScriptException implements Exception {
    String cause;

    InputScriptException(this.cause);

}

class TransactionException implements Exception {
    String cause;

    TransactionException(this.cause);
}

class LockTimeException implements Exception {
    String cause;

    LockTimeException(this.cause);
}

class InterpreterException implements Exception {
    String cause;

    InterpreterException(this.cause);
}

class BlockException implements Exception {
    String cause;

    BlockException(this.cause);
}

