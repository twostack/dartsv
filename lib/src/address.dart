import 'encoding/base58check.dart' as bs58check;
import 'package:hex/hex.dart';
import 'encoding/utils.dart';
import 'dart:convert';
import 'networks.dart';
import 'publickey.dart';
import 'exceptions.dart';

//TODO: No support P2SH addresses at the moment. I'll add when I need it.

class Address {
  List<NetworkType> _networkTypes;

//  SVPublicKey _publicKey;  //TODO: There is a possibility you're overloading this as both publicKeyHex *and* ripemd160(sha256(publicKeyHex)). Investigate !
  String _publicKeyHash;
  AddressType _addressType;
  NetworkType _networkType;

  int _version;

  //address param must be base58encoded and checksummed
  Address(String address) {
      _fromBase58(address);
  }

  String get address {
      return this._publicKeyHash;
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

  Address.fromHex(String hexPubKey, NetworkType networkType){
      _createFromHex(hexPubKey, networkType);
  }


  //TODO: WHAAAAA
  Address.fromCompressedPubKey(List<int> pubkeyBytes, NetworkType networkType) {
      _createFromHex(HEX.encode(pubkeyBytes), networkType);
      this._publicKeyHash = HEX.encode(hash160(pubkeyBytes));
  }

  Address.fromBase58(base58Address) {
    if (base58Address.length != 25){
        throw new AddressFormatException('Address should be 25 bytes long. Only [${base58Address.length}] bytes long.');
    }

    _fromBase58(base58Address);
  }

  String toBase58() {
    // A stringified buffer is:
    //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
    List<int> rawHash = HEX.decode(this._publicKeyHash).map((elem) => elem.toSigned(8)).toList();

    return _getEncoded(rawHash);
  }

  String toString() {

      List<int> rawAddress = HEX.decode(this._publicKeyHash).map((elem) => elem.toSigned(8)).toList();

      //ripemd160(sha256(this._publicKey))
//      var hashAddress = hash160(rawAddress);

      return _getEncoded(rawAddress);

  }

  /// @returns : Public Key Hash as a HEX String
  String toHex(){
      return this._publicKeyHash;
  }

  get networkTypes => this._networkTypes;
  get networkType => this._networkType;

  get addressType => this._addressType;

  /// @returns : hash160 value of the address. Not the publicly shareable address
  get pubkeyHash160 => this._publicKeyHash;

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


}
