import 'exceptions.dart';
import 'dart:typed_data';
import 'package:hex/hex.dart';

enum NetworkType { MAIN, TEST, REGTEST, SCALINGTEST}

enum AddressType { PUBKEY_HASH, SCRIPT_HASH }

enum KeyType { PUBLIC, PRIVATE }

enum NetworkAddressType {MAIN_PKH, MAIN_P2SH, TEST_PKH, TEST_P2SH}



/*
Oh, joy. The network type and address type fields are overloaded :facepalm:

      MAINNET
      -------
          Address Header = 0;
          P2SH Header = 5;

      TESTNET  / REG_TESTNET / SCALING_TESTNET
      ----------------------------------------
          Address Header = 111;
          P2SH Header = 196;
*/
class Networks{
  static List<NetworkType> getNetworkTypes(int version) {

      switch (version) {
          case 0  : return [NetworkType.MAIN ];
          case 111 : return [NetworkType.TEST, NetworkType.REGTEST, NetworkType.SCALINGTEST];
          case 5 : return [NetworkType.MAIN];
          case 196 : return [NetworkType.TEST, NetworkType.REGTEST, NetworkType.SCALINGTEST];

          default: throw new AddressFormatException('[$version] is not a valid network type.'); break;
      }


  }

  static AddressType getAddressType(int version){

      switch (version) {
          case 0  : return AddressType.PUBKEY_HASH;
          case 111 : return AddressType.PUBKEY_HASH;
          case 5 : return AddressType.SCRIPT_HASH;
          case 196 : return AddressType.SCRIPT_HASH;

          default: throw new AddressFormatException('[$version] is not a valid address type.'); break;
      }
  }

  //returns: appropriate number to prepend to an address to indicate network/address type
  static getNetworkVersion(NetworkAddressType type){
     switch(type) {
         case NetworkAddressType.MAIN_P2SH: return 5;
         case NetworkAddressType.MAIN_PKH : return 0;
         case NetworkAddressType.TEST_P2SH: return 196;
         case NetworkAddressType.TEST_PKH : return 111;
         default : return 0;
     }
  }


  static getNetworkAddressType(int versionByte){
      switch(versionByte) {
          case 5   : return  NetworkAddressType.MAIN_P2SH;
          case 0   : return  NetworkAddressType.MAIN_PKH;
          case 196 : return  NetworkAddressType.TEST_P2SH;
          case 111 : return  NetworkAddressType.TEST_PKH ;
      }
  }


}
