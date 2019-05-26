import 'dart:typed_data';
import 'dart:convert';

class WIFCodec{
    bool compressed;

    WIFCodec.fromBase58(params,base58) {
//        return new WIFCodec(params, base58);
    }


// Used by ECKey.getPrivateKeyEncoded()
    WIFCodec(params, List<int> keyBytes, bool compressed) {
        this.compressed = compressed;
    }

    static List<int> encode(List<int> keyBytes, bool compressed) {

        if (!compressed) {
            return keyBytes;
        } else {
            // Keys that have compressed public components have an extra 1 byte on the end in dumped form.
            List<int> bytes = List<int>(33);

            bytes.setRange(0, 32, keyBytes);
            bytes[32] = 1;
            return bytes;
        }
}


}
