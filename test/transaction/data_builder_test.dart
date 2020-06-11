

void main() {

}
/*
  describe('getData returns associated data', function () {
    it('works with this testnet transaction', function () {
      // testnet block: 00000000a36400fc06440512354515964bc36ecb0020bd0b0fd48ae201965f54
      // txhash: e362e21ff1d2ef78379d401d89b42ce3e0ce3e245f74b1f4cb624a8baa5d53ad (output 0);
      var script = Script.fromBuffer(Buffer.from('6a', 'hex'))
      var dataout = script.isDataOut()
      dataout.should.equal(true)
      var data = script.getData()
      data.should.deep.equal(Buffer.alloc(0))
    })
    it('for a P2PKH address', function () {
      var address = Address.fromString('1NaTVwXDDUJaXDQajoa9MqHhz4uTxtgK14')
      var script = Script.buildPublicKeyHashOut(address)
      expect(script.getData().equals(address.hashBuffer)).to.equal(true)
    })
    it('for a P2SH address', function () {
      var address = Address.fromString('3GhtMmAbWrUf6Y8vDxn9ETB14R6V7Br3mt')
      var script = new Script(address)
      expect(script.getData().equals(address.hashBuffer)).to.equal(true)
    })
    it('for a old-style opreturn output', function () {
      expect(Script('OP_RETURN 1 0xFF').getData().equals(Buffer.from([255]))).to.equal(true)
    })
    it('for a safe opreturn output', function () {
      expect(Script('OP_FALSE OP_RETURN 1 0xFF').getData()[0].equals(Buffer.from([255]))).to.equal(true)
    })
    it('fails if content is not recognized', function () {
      expect(function () {
        return Script('1 0xFF').getData()
      }).to.throw()
    })
  })

  describe('#buildDataOut', function () {
    it('should create script from no data', function () {
      var s = Script.buildDataOut()
      should.exist(s)
      s.toString().should.equal('OP_RETURN')
      s.isDataOut().should.equal(true)
    })
    it('should create script from empty data', function () {
      var data = Buffer.from('')
      var s = Script.buildDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_RETURN')
      s.isDataOut().should.equal(true)
    })
    it('should create script from some data', function () {
      var data = Buffer.from('bacacafe0102030405', 'hex')
      var s = Script.buildDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_RETURN 9 0xbacacafe0102030405')
      s.isDataOut().should.equal(true)
    })
    it('should create script from array of some data', function () {
      var data = Buffer.from('bacacafe0102030405', 'hex')
      var s = Script.buildDataOut([data, data])
      should.exist(s)
      s.toString().should.equal('OP_RETURN 9 0xbacacafe0102030405 9 0xbacacafe0102030405')
      s.isDataOut().should.equal(true)
    })
    it('should create script from array of some datas', function () {
      var data1 = Buffer.from('moneybutton.com')
      var data2 = Buffer.from('hello'.repeat(100))
      var s = Script.buildDataOut([data1, data2])
      should.exist(s)
      s.toString().should.equal('OP_RETURN 15 0x6d6f6e6579627574746f6e2e636f6d OP_PUSHDATA2 500 0x68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f')
      s.isDataOut().should.equal(true)
    })
    it('should create script from array of lots of data', function () {
      var data1 = Buffer.from('moneybutton.com')
      var data2 = Buffer.from('00'.repeat(90000), 'hex')
      var s = Script.buildDataOut([data1, data2])
      should.exist(s)
      s.toString().should.equal('OP_RETURN 15 0x6d6f6e6579627574746f6e2e636f6d OP_PUSHDATA4 90000 0x' + '00'.repeat(90000))
      s.isDataOut().should.equal(true)
    })
    it('should create script from string', function () {
      var data = 'hello world!!!'
      var s = Script.buildDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_RETURN 14 0x68656c6c6f20776f726c64212121')
      s.isDataOut().should.equal(true)
    })
    it('should create script from an array of strings', function () {
      var data = 'hello world!!!'
      var s = Script.buildDataOut([data, data])
      should.exist(s)
      s.toString().should.equal('OP_RETURN 14 0x68656c6c6f20776f726c64212121 14 0x68656c6c6f20776f726c64212121')
      s.isDataOut().should.equal(true)
    })
    it('should create script from a hex string', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildDataOut(hexString, 'hex')
      should.exist(s)
      s.toString().should.equal('OP_RETURN 8 0xabcdef0123456789')
      s.isDataOut().should.equal(true)
    })
    it('should create script from an array of a hex string', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildDataOut([hexString], 'hex')
      should.exist(s)
      s.toString().should.equal('OP_RETURN 8 0xabcdef0123456789')
      s.isDataOut().should.equal(true)
    })
    it('should create script from an array of hex strings', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildDataOut([hexString, hexString], 'hex')
      should.exist(s)
      s.toString().should.equal('OP_RETURN 8 0xabcdef0123456789 8 0xabcdef0123456789')
      s.isDataOut().should.equal(true)
    })
  })
  describe('#buildSafeDataOut', function () {
    it('should create script from no data', function () {
      var s = Script.buildSafeDataOut()
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from empty data', function () {
      var data = Buffer.from('')
      var s = Script.buildSafeDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from some data', function () {
      var data = Buffer.from('bacacafe0102030405', 'hex')
      var s = Script.buildSafeDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 9 0xbacacafe0102030405')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from array of some data', function () {
      var data = Buffer.from('bacacafe0102030405', 'hex')
      var s = Script.buildSafeDataOut([data, data])
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 9 0xbacacafe0102030405 9 0xbacacafe0102030405')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from array of some datas', function () {
      var data1 = Buffer.from('moneybutton.com')
      var data2 = Buffer.from('hello'.repeat(100))
      var s = Script.buildSafeDataOut([data1, data2])
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 15 0x6d6f6e6579627574746f6e2e636f6d OP_PUSHDATA2 500 0x68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f68656c6c6f')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from array of lots of data', function () {
      var data1 = Buffer.from('moneybutton.com')
      var data2 = Buffer.from('00'.repeat(90000), 'hex')
      var s = Script.buildSafeDataOut([data1, data2])
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 15 0x6d6f6e6579627574746f6e2e636f6d OP_PUSHDATA4 90000 0x' + '00'.repeat(90000))
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from string', function () {
      var data = 'hello world!!!'
      var s = Script.buildSafeDataOut(data)
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 14 0x68656c6c6f20776f726c64212121')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from an array of strings', function () {
      var data = 'hello world!!!'
      var s = Script.buildSafeDataOut([data, data])
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 14 0x68656c6c6f20776f726c64212121 14 0x68656c6c6f20776f726c64212121')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from a hex string', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildSafeDataOut(hexString, 'hex')
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 8 0xabcdef0123456789')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from an array of a hex string', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildSafeDataOut([hexString], 'hex')
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 8 0xabcdef0123456789')
      s.isSafeDataOut().should.equal(true)
    })
    it('should create script from an array of hex strings', function () {
      var hexString = 'abcdef0123456789'
      var s = Script.buildSafeDataOut([hexString, hexString], 'hex')
      should.exist(s)
      s.toString().should.equal('OP_0 OP_RETURN 8 0xabcdef0123456789 8 0xabcdef0123456789')
      s.isSafeDataOut().should.equal(true)
    })
  })
  describe('#isDataOut', function () {
    it('should know this is a (blank) OP_RETURN script', function () {
      Script('OP_RETURN').isDataOut().should.equal(true)
    })

    it('validates that this two part OP_RETURN is standard', function () {
      Script.fromASM('OP_RETURN 026d02 0568656c6c6f').isDataOut().should.equal(true)
    })

    it('validates that this 40-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(40)
      buf.fill(0)
      Script('OP_RETURN 40 0x' + buf.toString('hex')).isDataOut().should.equal(true)
    })

    it('validates that this 80-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(80)
      buf.fill(0)
      Script('OP_RETURN OP_PUSHDATA1 80 0x' + buf.toString('hex')).isDataOut().should.equal(true)
    })

    it('validates that this 220-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(220)
      buf.fill(0)
      Script('OP_RETURN OP_PUSHDATA1 220 0x' + buf.toString('hex')).isDataOut().should.equal(true)
    })

    it('validates that this 40-byte long OP_CHECKMULTISIG is not standard op_return', function () {
      var buf = Buffer.alloc(40)
      buf.fill(0)
      Script('OP_CHECKMULTISIG 40 0x' + buf.toString('hex')).isDataOut().should.equal(false)
    })

    it('validates that this 221-byte OP_RETURN is a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(221)
      buf.fill(0)
      Script('OP_RETURN OP_PUSHDATA1 221 0x' + buf.toString('hex')).isDataOut().should.equal(true)
    })

    it('validates that this 99994-byte OP_RETURN is a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(100000 - 6)
      buf.fill(0)
      Script(`OP_RETURN OP_PUSHDATA4 ${buf.length} 0x` + buf.toString('hex')).isDataOut().should.equal(true)
    })

    it('validates that this 99995-byte OP_RETURN is not a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(100000 - 5)
      buf.fill(0)
      Script(`OP_RETURN OP_PUSHDATA4 ${buf.length} 0x` + buf.toString('hex')).isDataOut().should.equal(false)
    })
  })

  describe('#isSafeDataOut', function () {
    it('should know this is a (blank) OP_RETURN script', function () {
      Script('OP_FALSE OP_RETURN').isSafeDataOut().should.equal(true)
    })

    it('validates that this two part OP_RETURN is standard', function () {
      Script.fromASM('OP_FALSE OP_RETURN 026d02 0568656c6c6f').isSafeDataOut().should.equal(true)
    })

    it('validates that this 40-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(40)
      buf.fill(0)
      Script('OP_FALSE OP_RETURN 40 0x' + buf.toString('hex')).isSafeDataOut().should.equal(true)
    })

    it('validates that this 80-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(80)
      buf.fill(0)
      Script('OP_FALSE OP_RETURN OP_PUSHDATA1 80 0x' + buf.toString('hex')).isSafeDataOut().should.equal(true)
    })

    it('validates that this 220-byte OP_RETURN is standard', function () {
      var buf = Buffer.alloc(220)
      buf.fill(0)
      Script('OP_FALSE OP_RETURN OP_PUSHDATA1 220 0x' + buf.toString('hex')).isSafeDataOut().should.equal(true)
    })

    it('validates that this 40-byte long OP_CHECKMULTISIG is not standard op_return', function () {
      var buf = Buffer.alloc(40)
      buf.fill(0)
      Script('OP_CHECKMULTISIG 40 0x' + buf.toString('hex')).isSafeDataOut().should.equal(false)
    })

    it('validates that this 221-byte OP_RETURN is a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(221)
      buf.fill(0)
      Script('OP_FALSE OP_RETURN OP_PUSHDATA1 221 0x' + buf.toString('hex')).isSafeDataOut().should.equal(true)
    })

    it('validates that this 99994-byte OP_RETURN is a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(100000 - 6)
      buf.fill(0)
      Script(`OP_FALSE OP_RETURN OP_PUSHDATA4 ${buf.length} 0x` + buf.toString('hex')).isSafeDataOut().should.equal(true)
    })

    it('validates that this 99995-byte OP_RETURN is not a valid standard OP_RETURN', function () {
      var buf = Buffer.alloc(100000 - 5)
      buf.fill(0)
      Script(`OP_FALSE OP_RETURN OP_PUSHDATA4 ${buf.length} 0x` + buf.toString('hex')).isSafeDataOut().should.equal(false)
    })
  })

     */
