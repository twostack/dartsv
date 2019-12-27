import 'exceptions.dart';
import 'dart:typed_data';
import 'package:hex/hex.dart';

enum NetworkType { MAIN, TEST, REGTEST, SCALINGTEST }

enum AddressType { PUBKEY_HASH, SCRIPT_HASH }

enum KeyType { PUBLIC, PRIVATE }

enum NetworkAddressType { MAIN_PKH, MAIN_P2SH, TEST_PKH, TEST_P2SH }


/// Utility class used to inject strong typing into the [Address] class' representation of network and address types.
///
/// NOTE: The network type and address type fields are overloaded in the way that wallet's interpret them.
///       This is not consensus-level stuff. Used only in Address representations by wallets.
///
///       MAINNET
///       -------
///           Address Header = 0;
///           P2SH Header = 5;
///
///       TESTNET  / REG_TESTNET / SCALING_TESTNET
///       ----------------------------------------
///           Address Header = 111;
///           P2SH Header = 196;
class Networks {

    /// Retrieve the list of network types corresponding to the version byte
    ///
    /// [version] - The version byte from the head of a serialized [Address]
    ///
    /// Returns a list of possible network types for the corresponding version byte
    static List<NetworkType> getNetworkTypes(int version) {
        switch (version) {
            case 0 :
                return [NetworkType.MAIN];
            case 111 :
                return [NetworkType.TEST, NetworkType.REGTEST, NetworkType.SCALINGTEST];
            case 5 :
                return [NetworkType.MAIN];
            case 196 :
                return [NetworkType.TEST, NetworkType.REGTEST, NetworkType.SCALINGTEST];

            default:
                throw new AddressFormatException('[$version] is not a valid network type.');
                break;
        }
    }

    /// Retrieve the address type corresponding to a specific version.
    ///
    /// NOTE: This relates to "standard" transaction types as defined by Bitcoin Core. Bitcoin SV will
    ///       be doing away with the notion of "standard" transaction types during "Genesis" protocol restoration in February 2020.
    ///       As such, wallet developers should note that these type of transaction representation will become increasingly meaningless
    ///       as "non-standard" transaction types start appearing on the Bitcoin SV blockchain.
    ///
    /// [version] - The version byte from the head of a serialized [Address]
    ///
    /// Returns the address type corresponding to a specific [Address] version byte.
    static AddressType getAddressType(int version) {
        switch (version) {
            case 0 :
                return AddressType.PUBKEY_HASH;
            case 111 :
                return AddressType.PUBKEY_HASH;
            case 5 :
                return AddressType.SCRIPT_HASH;
            case 196 :
                return AddressType.SCRIPT_HASH;

            default:
                throw new AddressFormatException('[$version] is not a valid address type.');
                break;
        }
    }

    /// This method retrieves the version byte corresponding to the NetworkAddressType
    ///
    /// [type] - The network address type
    ///
    /// Returns the version byte to prepend to a serialized [Address]
    static int getNetworkVersion(NetworkAddressType type) {
        switch (type) {
            case NetworkAddressType.MAIN_P2SH:
                return 5;
            case NetworkAddressType.MAIN_PKH :
                return 0;
            case NetworkAddressType.TEST_P2SH:
                return 196;
            case NetworkAddressType.TEST_PKH :
                return 111;
            default :
                return 0;
        }
    }


    /// Given an address' version byte this method retrieves the corresponding network type.
    ///
    /// [versionByte] - The version byte at the head of a wallet address
    ///
    /// Returns the network address type
     static NetworkAddressType getNetworkAddressType(int versionByte) {
        switch (versionByte) {
            case 5 :
                return NetworkAddressType.MAIN_P2SH;
            case 0 :
                return NetworkAddressType.MAIN_PKH;
            case 196 :
                return NetworkAddressType.TEST_P2SH;
            case 111 :
                return NetworkAddressType.TEST_PKH;
            default:
                return NetworkAddressType.MAIN_PKH;
        }
    }


}
