/**
 * totp.js — TOTP（RFC 6238）+ SHA-1 / SHA-256 + Base32 的最小实现，无任何依赖。
 *
 * 默认用 SHA1，与页面及二维码参数保持一致；也支持显式选择 SHA256。
 * 不支持的算法会抛错，避免生成与调用方预期不同的验证码。
 */
;(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory()
  else root.TOTPLite = factory()
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict'

  var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

  /** 字节数组 → Base32（不带 '=' 填充） */
  function base32Encode(bytes) {
    var out = ''
    var bits = 0
    var value = 0
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i]
      bits += 8
      while (bits >= 5) {
        out += B32_ALPHABET[(value >>> (bits - 5)) & 31]
        bits -= 5
      }
    }
    if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31]
    return out
  }

  /** Base32 → 字节数组（忽略空格、'-'、'=' 与大小写） */
  function base32Decode(str) {
    var clean = String(str).toUpperCase().replace(/[\s\-=]/g, '')
    var out = []
    var bits = 0
    var value = 0
    for (var i = 0; i < clean.length; i++) {
      var idx = B32_ALPHABET.indexOf(clean[i])
      if (idx < 0) continue
      value = (value << 5) | idx
      bits += 5
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff)
        bits -= 8
      }
    }
    return new Uint8Array(out)
  }

  /** 32 字节（256 位）随机密钥，转 Base32 */
  function randomSecret(byteLength) {
    var n = byteLength || 32
    var bytes = new Uint8Array(n)
    var cryptoObj = typeof crypto !== 'undefined' ? crypto : null
    if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
      throw new Error('当前浏览器不支持安全随机数，无法生成密钥。')
    }
    cryptoObj.getRandomValues(bytes)
    return base32Encode(bytes)
  }

  // ---------- 消息填充（SHA-1 / SHA-256 共用） ----------

  function padMessage(bytes) {
    var len = bytes.length
    var padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64)
    padded.set(bytes)
    padded[len] = 0x80

    // 64 位大端比特长度
    var hi = Math.floor(len / 536870912) // len * 8 / 2^32
    var lo = (len << 3) >>> 0
    var tail = padded.length
    padded[tail - 8] = (hi >>> 24) & 0xff
    padded[tail - 7] = (hi >>> 16) & 0xff
    padded[tail - 6] = (hi >>> 8) & 0xff
    padded[tail - 5] = hi & 0xff
    padded[tail - 4] = (lo >>> 24) & 0xff
    padded[tail - 3] = (lo >>> 16) & 0xff
    padded[tail - 2] = (lo >>> 8) & 0xff
    padded[tail - 1] = lo & 0xff
    return padded
  }

  function readWord(buf, offset) {
    return (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]
  }

  function writeWord(out, index, value) {
    out[index * 4] = (value >>> 24) & 0xff
    out[index * 4 + 1] = (value >>> 16) & 0xff
    out[index * 4 + 2] = (value >>> 8) & 0xff
    out[index * 4 + 3] = value & 0xff
  }

  // ---------- SHA-1 ----------

  function rotl(x, n) {
    return (x << n) | (x >>> (32 - n))
  }

  /** SHA-1，返回 20 字节 Uint8Array */
  function sha1(bytes) {
    var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    var padded = padMessage(bytes)
    var w = new Array(80)

    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = readWord(padded, off + i * 4)
      for (var t = 16; t < 80; t++) {
        w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
      }

      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4]
      for (var r = 0; r < 80; r++) {
        var f, k
        if (r < 20) {
          f = (b & c) | (~b & d)
          k = 0x5a827999
        } else if (r < 40) {
          f = b ^ c ^ d
          k = 0x6ed9eba1
        } else if (r < 60) {
          f = (b & c) | (b & d) | (c & d)
          k = 0x8f1bbcdc
        } else {
          f = b ^ c ^ d
          k = 0xca62c1d6
        }
        var temp = (rotl(a, 5) + f + e + k + w[r]) | 0
        e = d
        d = c
        c = rotl(b, 30)
        b = a
        a = temp
      }
      H[0] = (H[0] + a) | 0
      H[1] = (H[1] + b) | 0
      H[2] = (H[2] + c) | 0
      H[3] = (H[3] + d) | 0
      H[4] = (H[4] + e) | 0
    }

    var out = new Uint8Array(20)
    for (var j = 0; j < 5; j++) writeWord(out, j, H[j])
    return out
  }

  // ---------- SHA-256 ----------

  var K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n))
  }

  /** SHA-256，返回 32 字节 Uint8Array */
  function sha256(bytes) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    var padded = padMessage(bytes)
    var w = new Array(64)

    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = readWord(padded, off + i * 4)
      for (var t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0
      }

      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7]
      for (var r = 0; r < 64; r++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        var ch = (e & f) ^ (~e & g)
        var temp1 = (h + S1 + ch + K256[r] + w[r]) | 0
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var temp2 = (S0 + maj) | 0
        h = g
        g = f
        f = e
        e = (d + temp1) | 0
        d = c
        c = b
        b = a
        a = (temp1 + temp2) | 0
      }
      H[0] = (H[0] + a) | 0
      H[1] = (H[1] + b) | 0
      H[2] = (H[2] + c) | 0
      H[3] = (H[3] + d) | 0
      H[4] = (H[4] + e) | 0
      H[5] = (H[5] + f) | 0
      H[6] = (H[6] + g) | 0
      H[7] = (H[7] + h) | 0
    }

    var out = new Uint8Array(32)
    for (var j = 0; j < 8; j++) writeWord(out, j, H[j])
    return out
  }

  // ---------- HMAC ----------

  function hmac(key, message, hashFn) {
    var blockSize = 64
    var k = key
    if (k.length > blockSize) k = hashFn(k)

    var inner = new Uint8Array(blockSize + message.length)
    var outer = new Uint8Array(blockSize)
    for (var i = 0; i < blockSize; i++) {
      var b = i < k.length ? k[i] : 0
      outer[i] = b ^ 0x5c
      inner[i] = b ^ 0x36
    }
    inner.set(message, blockSize)
    var innerHash = hashFn(inner)

    var out = new Uint8Array(blockSize + innerHash.length)
    out.set(outer)
    out.set(innerHash, blockSize)
    return hashFn(out)
  }

  function hmacSha1(key, message) {
    return hmac(key, message, sha1)
  }

  function hmacSha256(key, message) {
    return hmac(key, message, sha256)
  }

  /**
   * 生成 TOTP 验证码
   * @param {string} secretBase32 Base32 密钥
   * @param {number} [timestamp] 毫秒时间戳，默认当前时间
   * @param {number} [period=30] 步长（秒）
   * @param {number} [digits=6] 位数
   * @param {string} [algorithm='SHA1'] SHA1 | SHA256
   */
  function totp(secretBase32, timestamp, period, digits, algorithm) {
    var step = period || 30
    var length = digits || 6
    var algo = algorithm === undefined ? 'SHA1' : String(algorithm).trim().toUpperCase()
    var hashFn
    if (algo === 'SHA1') hashFn = sha1
    else if (algo === 'SHA256') hashFn = sha256
    else throw new Error('不支持的 TOTP 算法：' + algo)
    var now = typeof timestamp === 'number' ? timestamp : Date.now()
    var counter = Math.floor(now / 1000 / step)

    var msg = new Uint8Array(8)
    var hi = Math.floor(counter / 4294967296)
    var lo = counter % 4294967296
    msg[0] = (hi >>> 24) & 0xff
    msg[1] = (hi >>> 16) & 0xff
    msg[2] = (hi >>> 8) & 0xff
    msg[3] = hi & 0xff
    msg[4] = (lo >>> 24) & 0xff
    msg[5] = (lo >>> 16) & 0xff
    msg[6] = (lo >>> 8) & 0xff
    msg[7] = lo & 0xff

    var digest = hmac(base32Decode(secretBase32), msg, hashFn)
    var offset = digest[digest.length - 1] & 0x0f
    var binary =
      ((digest[offset] & 0x7f) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3]
    binary = binary >>> 0
    var code = String(binary % Math.pow(10, length))
    while (code.length < length) code = '0' + code
    return code
  }

  return {
    base32Encode: base32Encode,
    base32Decode: base32Decode,
    randomSecret: randomSecret,
    sha1: sha1,
    sha256: sha256,
    hmacSha1: hmacSha1,
    hmacSha256: hmacSha256,
    totp: totp
  }
})
