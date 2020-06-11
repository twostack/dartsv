
void main() {

}
/*

  describe('#buildScriptHashOut', function () {
    it('should create script from another script', function () {
      var inner = new Script('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG')
      var s = Script.buildScriptHashOut(inner)
      should.exist(s)
      s.toString().should.equal('OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL')
      s.isScriptHashOut().should.equal(true)
    })

    it('inherits network property from other script', function () {
      var s1 = Script.fromAddress(new Address('1FSMWkjVPAxzUNjbxT52p3mVKC971rfW3S'))
      var s2 = Script.buildScriptHashOut(s1)
      should.exist(s1._network)
      s1._network.should.equal(s2._network)
    })

    it('inherits network property form an address', function () {
      var address = new Address('34Nn91aTGaULqWsZiunrBPHzFBDrZ3B8XS')
      var script = Script.buildScriptHashOut(address)
      should.exist(script._network)
      script._network.should.equal(address.network)
    })
  })
  describe('#toScriptHashOut', function () {
    it('should create script from another script', function () {
      var s = new Script('OP_DUP OP_HASH160 20 0x06c06f6d931d7bfba2b5bd5ad0d19a8f257af3e3 OP_EQUALVERIFY OP_CHECKSIG')
      var sho = s.toScriptHashOut()
      sho.toString().should.equal('OP_HASH160 20 0x45ea3f9133e7b1cef30ba606f8433f993e41e159 OP_EQUAL')
      sho.isScriptHashOut().should.equal(true)
    })
  })
  describe('#isScriptHashIn', function () {
    it('should identify this known scripthashin', function () {
      var sstr = 'OP_0 73 0x30460221008ca148504190c10eea7f5f9c283c719a37be58c3ad617928011a1bb9570901d2022100ced371a23e86af6f55ff4ce705c57d2721a09c4d192ca39d82c4239825f75a9801 72 0x30450220357011fd3b3ad2b8f2f2d01e05dc6108b51d2a245b4ef40c112d6004596f0475022100a8208c93a39e0c366b983f9a80bfaf89237fcd64ca543568badd2d18ee2e1d7501 OP_PUSHDATA1 105 0x5221024c02dff2f0b8263a562a69ec875b2c95ffad860f428acf2f9e8c6492bd067d362103546324a1351a6b601c623b463e33b6103ca444707d5b278ece1692f1aa7724a42103b1ad3b328429450069cc3f9fa80d537ee66ba1120e93f3f185a5bf686fb51e0a53ae'
      var s = Script(sstr)
      s.toString().should.equal(sstr)
      s.isScriptHashIn().should.equal(true)
    })

    it('should identify this known non-scripthashin', function () {
      Script('20 0000000000000000000000000000000000000000 OP_CHECKSIG').isScriptHashIn().should.equal(false)
    })

    it('should identify this problematic non-scripthashin scripts', function () {
      var s = new Script('71 0x3044022017053dad84aa06213749df50a03330cfd24d6' +
        'b8e7ddbb6de66c03697b78a752a022053bc0faca8b4049fb3944a05fcf7c93b2861' +
        '734d39a89b73108f605f70f5ed3401 33 0x0225386e988b84248dc9c30f784b06e' +
        '02fdec57bbdbd443768eb5744a75ce44a4c')
      var s2 = new Script('OP_RETURN 32 0x19fdb20634911b6459e6086658b3a6ad2dc6576bd6826c73ee86a5f9aec14ed9')
      s.isScriptHashIn().should.equal(false)
      s2.isScriptHashIn().should.equal(false)
    })
    it('identifies this other problematic non-p2sh in', function () {
      var s = Script.fromString('73 0x3046022100dc7a0a812de14acc479d98ae209402cc9b5e0692bc74b9fe0a2f083e2f9964b002210087caf04a711bebe5339fd7554c4f7940dc37be216a3ae082424a5e164faf549401')
      s.isScriptHashIn().should.equal(false)
    })
  })

  describe('#isScripthashOut', function () {
    it('should identify this known p2shout as p2shout', function () {
      Script('OP_HASH160 20 0x0000000000000000000000000000000000000000 OP_EQUAL').isScriptHashOut().should.equal(true)
    })

    it('should identify result of .isScriptHashOut() as p2sh', function () {
      Script('OP_DUP OP_HASH160 20 0x0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG')
        .toScriptHashOut().isScriptHashOut().should.equal(true)
    })

    it('should identify these known non-p2shout as not p2shout', function () {
      Script('OP_HASH160 20 0x0000000000000000000000000000000000000000 OP_EQUAL OP_EQUAL').isScriptHashOut().should.equal(false)
      Script('OP_HASH160 21 0x000000000000000000000000000000000000000000 OP_EQUAL').isScriptHashOut().should.equal(false)
    })
  })
 */