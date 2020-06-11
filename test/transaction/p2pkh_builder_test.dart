
void main() {

}
/*

  describe('#buildPublicKeyHashOut', function () {
    it('should create script from livenet address', function () {
      var address = Address.fromString('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14')
      var s = Script.buildPublicKeyHashOut(address)
      should.exist(s)
      s.toString().should.equal('OP_DUP OP_HASH160 20 0xecae7d092947b7ee4998e254aa48900d26d2ce1d OP_EQUALVERIFY OP_CHECKSIG')
      s.isPublicKeyHashOut().should.equal(true)
      s.toAddress().toString().should.equal('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14')
    })
    it('should create script from testnet address', function () {
      var address = Address.fromString('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33')
      var s = Script.buildPublicKeyHashOut(address)
      should.exist(s)
      s.toString().should.equal('OP_DUP OP_HASH160 20 0xb96b816f378babb1fe585b7be7a2cd16eb99b3e4 OP_EQUALVERIFY OP_CHECKSIG')
      s.isPublicKeyHashOut().should.equal(true)
      s.toAddress().toString().should.equal('mxRN6AQJaDi5R6KmvMaEmZGe3n5ScV9u33')
    })
    it('should create script from public key', function () {
      var pubkey = new PublicKey('022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da')
      var s = Script.buildPublicKeyHashOut(pubkey)
      should.exist(s)
      s.toString().should.equal('OP_DUP OP_HASH160 20 0x9674af7395592ec5d91573aa8d6557de55f60147 OP_EQUALVERIFY OP_CHECKSIG')
      s.isPublicKeyHashOut().should.equal(true)
      should.exist(s._network)
      s._network.should.equal(pubkey.network)
    })
  })

  describe('#isPublicKeyHashIn', function () {
    it('should identify this known pubkeyhashin (uncompressed pubkey version)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known pubkeyhashin (hybrid pubkey version w/06)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x06e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known pubkeyhashin (hybrid pubkey version w/07)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x07e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known pubkeyhashin (compressed pubkey w/ 0x02)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 21 0x02aec6b86621e7fef63747fbfd6a6e7d54c8e1052044ef2dd2c5e46656ef1194d4').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known pubkeyhashin (compressed pubkey w/ 0x03)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 21 0x03e724d93c4fda5f1236c525de7ffac6c5f1f72b0f5cdd1fc4b4f5642b6d055fcc').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known non-pubkeyhashin (bad ops length)', function () {
      Script('73 0x3046022100bb3c194a30e460d81d34be0a230179c043a656f67e3c5c8bf47eceae7c4042ee0221008bf54ca11b2985285be0fd7a212873d243e6e73f5fad57e8eb14c4f39728b8c601 65 0x04e365859b3c78a8b7c202412b949ebca58e147dba297be29eee53cd3e1d300a6419bc780cc9aec0dc94ed194e91c8f6433f1b781ee00eac0ead2aae1e8e0712c6 OP_CHECKSIG').isPublicKeyHashIn().should.equal(false)
    })

    it('should identify this known pubkey', function () {
      Script('70 0x3043021f336721e4343f67c835cbfd465477db09073dc38a936f9c445d573c1c8a7fdf022064b0e3cb6892a9ecf870030e3066bc259e1f24841c9471d97f9be08b73f6530701 33 0x0370b2e1dcaa8f51cb0ead1221dd8cb31721502b3b5b7d4b374d263dfec63a4369').isPublicKeyHashIn().should.equal(true)
    })

    it('should identify this known non-pubkeyhashin (bad version)', function () {
      Script('70 0x3043021f336721e4343f67c835cbfd465477db09073dc38a936f9c445d573c1c8a7fdf022064b0e3cb6892a9ecf870030e3066bc259e1f24841c9471d97f9be08b73f6530701 33 0x1270b2e1dcaa8f51cb0ead1221dd8cb31721502b3b5b7d4b374d263dfec63a4369').isPublicKeyHashIn().should.equal(false)
    })

    it('should identify this known non-pubkeyhashin (bad signature version)', function () {
      Script('70 0x4043021f336721e4343f67c835cbfd465477db09073dc38a936f9c445d573c1c8a7fdf022064b0e3cb6892a9ecf870030e3066bc259e1f24841c9471d97f9be08b73f6530701 33 0x0370b2e1dcaa8f51cb0ead1221dd8cb31721502b3b5b7d4b374d263dfec63a4369').isPublicKeyHashIn().should.equal(false)
    })

    it('should identify this known non-pubkeyhashin (no public key)', function () {
      Script('70 0x3043021f336721e4343f67c835cbfd465477db09073dc38a936f9c445d573c1c8a7fdf022064b0e3cb6892a9ecf870030e3066bc259e1f24841c9471d97f9be08b73f6530701 OP_CHECKSIG').isPublicKeyHashIn().should.equal(false)
    })

    it('should identify this known non-pubkeyhashin (no signature)', function () {
      Script('OP_DROP OP_CHECKSIG').isPublicKeyHashIn().should.equal(false)
    })
  })

  describe('#isPublicKeyHashOut', function () {
    it('should identify this known pubkeyhashout as pubkeyhashout', function () {
      Script('OP_DUP OP_HASH160 20 0x0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG').isPublicKeyHashOut().should.equal(true)
    })

    it('should identify this known non-pubkeyhashout as not pubkeyhashout 1', function () {
      Script('OP_DUP OP_HASH160 20 0x0000000000000000000000000000000000000000').isPublicKeyHashOut().should.equal(false)
    })

    it('should identify this known non-pubkeyhashout as not pubkeyhashout 2', function () {
      Script('OP_DUP OP_HASH160 2 0x0000 OP_EQUALVERIFY OP_CHECKSIG').isPublicKeyHashOut().should.equal(false)
    })
  })
 */