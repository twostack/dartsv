import 'encoding/base58check.dart' as bs58check;
import 'package:hex/hex.dart';
import 'encoding/utils.dart';
import 'dart:convert';
import 'networks.dart';
import 'publickey.dart';
import 'exceptions.dart';

//TODO: No support P2SH addresses at the moment. I'll add when I need it.


/// This class abstracts away the internals of address encoding and provides
/// a convenient means to both encode and decode information from a bitcoin address.
///
/// Bitcoin addresses are a construct which facilitates interoperability
/// between different wallets. I.e. an agreement amongst wallet providers to have a
/// common means of sharing the hashed public key value needed to send someone bitcoin using one
/// of the standard public-key-based transaction types.
///
/// The Address does not contain a public key, only a hashed value of a public key
/// which is derived as explained below.
///
/// Bitcoin addresses are not part of the consensus rules of bitcoin.
///
/// Bitcoin addresses are encoded as follows
/// * 1st byte - indicates the network type which is either MAINNET or TESTNET
/// * next 20 bytes - the hash value computed by taking the `ripemd160(sha256(PUBLIC_KEY))`
/// * last 4 bytes  - a checksum value taken from the first four bytes of sha256(sha256(previous_21_bytes))

class Address {
  List<NetworkType> _networkTypes;

  String _publicKeyHash;
  AddressType _addressType;
  NetworkType _networkType;
  int _version;

  /// Constructs a new Address object
  ///
  /// [address] is the base58encoded bitcoin address.
  ///
  Address(String address) {
      _fromBase58(address);
  }


  /// Constructs a new Address object from a public key.
  ///
  /// [hexPubKey] is the hexadecimal encoding of a public key.
  ///
  /// [networkType] is used to distinguish between MAINNET and TESTNET.
  ///
  /// Also see [NetworkType]
  Address.fromHex(String hexPubKey, NetworkType networkType){
      _createFromHex(hexPubKey, networkType);
  }


  /// Constructs a new Address object from a compressed public key value
  ///
  /// [pubkeyBytes] is a byte-buffer of a public key
  ///
  /// [networkType] is used to distinguish between MAINNET and TESTNET.
  ///
  /// Also see [NetworkType]
  Address.fromCompressedPubKey(List<int> pubkeyBytes, NetworkType networkType) {
      _createFromHex(HEX.encode(pubkeyBytes), networkType);
      this._publicKeyHash = HEX.encode(hash160(pubkeyBytes));
  }

  /// Constructs a new Address object from a base58-encoded string.
  ///
  /// Base58-encoded strings are the "standard" means of sharing bitoin addresses amongst
  /// wallets. This is typically done either using the string of directly, or by using a
  /// QR-encoded form of this string.
  ///
  /// Typically, if someone is sharing their bitcoin address with you, this is the method
  /// you would use to instantiate an [Address] object for use with [Transaction] objects.
  ///
  Address.fromBase58(String base58Address) {
      if (base58Address.length != 25){
          throw new AddressFormatException('Address should be 25 bytes long. Only [${base58Address.length}] bytes long.');
      }

      _fromBase58(base58Address);
  }


  /// Serialise this address object to a base58-encoded string
  ///
  /// Base58-encoded strings are the "standard" means of sharing bitoin addresses amongst
  /// wallets. This is typically done either using the string of directly, or by using a
  /// QR-encoded form of this string.
  ///
  /// When sharing a bitcoin address with an external party either as a QR-code or via
  /// email etc., this would typically be the form in which you share the address.
  ///
  String toBase58() {
      // A stringified buffer is:
      //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
      List<int> rawHash = HEX.decode(this._publicKeyHash).map((elem) => elem.toSigned(8)).toList();

      return _getEncoded(rawHash);
  }

  /// Serialise this address object to a base58-encoded string.
  /// This method is an alias for the [toBase58()] method
  String toString() {
      return toBase58();
  }

  /// Returns the public key hash [ripemd160(sha256(public_key))] encoded as a  hexadecimal string
  String toHex(){
      return this._publicKeyHash;
  }


  String _getEncoded(List<int> hashAddress) {

      List<int> addressBytes = List<int>(1 + hashAddress.length + 4);
      addressBytes[0] = this._version;

      //copy all of raw address content, taking care not to
      //overwrite the version byte at start
      addressBytes.fillRange(1, addressBytes.length, 0);
      addressBytes.setRange(1, hashAddress.length + 1, hashAddress);

      //checksum calculation...
      //doubleSha everything except the last four checksum bytes
      var doubleShaAddr = sha256Twice(addressBytes.sublist(0, hashAddress.length + 1));
      var checksum = doubleShaAddr.sublist(0, 4).map((elem) => elem.toSigned(8)).toList();

      addressBytes.setRange(hashAddress.length + 1, addressBytes.length, checksum);
      var encoded = bs58check.encode(addressBytes);
      var utf8Decoded = utf8.decode(encoded);

      return utf8Decoded;
  }

  _fromBase58(String address){

      address = address.trim();

      List<int> versionAndDataBytes = bs58check.decodeChecked(address);
      int versionByte = versionAndDataBytes[0].toUnsigned(8);

      this._version = versionByte & 0xFF;
      this._networkTypes = Networks.getNetworkTypes(this._version);
      this._addressType = Networks.getAddressType(this._version);
      this._networkType = Networks.getNetworkTypes(this._version)[0];
      var stripVersion = versionAndDataBytes.sublist(1, versionAndDataBytes.length);
      this._publicKeyHash = HEX.encode(stripVersion.map((elem) => elem.toUnsigned(8)).toList());
  }

  _createFromHex(String hexPubKey, NetworkType networkType){


      //make an assumption about PKH vs PSH for naked address generation
      var versionByte;
      if (networkType == NetworkType.MAIN)
          versionByte = Networks.getNetworkVersion(NetworkAddressType.MAIN_PKH);
      else
          versionByte = Networks.getNetworkVersion(NetworkAddressType.TEST_PKH);

      this._version = versionByte & 0XFF;
      this._publicKeyHash = HEX.encode(hash160(HEX.decode(hexPubKey)));
      this._addressType = Networks.getAddressType(this._version);
      this._networkType = networkType;
  }



  /// Returns a hash of the Public Key
  ///
  /// The sha256 digest of the public key is computed, and the result of that
  /// computation is then passed to the [ripemd160()] digest function.
  ///
  /// The returned value is HEX-encoded
  String get address => this._publicKeyHash;

  /// An alias for the [address] property
  String get pubkeyHash160 => this._publicKeyHash;


  /// Returns a list of network types supported by this address
  ///
  /// This is only really needed because BSV has three different test networks
  /// which technically share the same integer value when encoded, but for
  /// which it is useful to have a type-level distinction during development
  List<NetworkType> get networkTypes => this._networkTypes;


  /// Returns the specific Network Type that this Address is compatible with
  NetworkType get networkType => this._networkType;

  /// Returns the type of "standard transaction" this Address is meant to be used for.
  ///
  /// Addresses are not part of the consensus rules of bitcoin. However with the introduction
  /// of "standard transaction types" wallets have fallen in line with providing
  /// address types that distinguish the types of transactions the coins are meant
  /// to be associated with
  ///
  /// See documentation for [Transaction]
  AddressType get addressType => this._addressType;


}
