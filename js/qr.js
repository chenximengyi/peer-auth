/**
 * qr.js — 极简 QR Code 编码器（byte 模式，无依赖）
 * 只做本 demo 需要的事：把一段 UTF-8 字符串编成二维码点阵。
 * 算法参考 ISO/IEC 18004 与 Project Nayuki 的 qrcodegen 思路。
 */
;(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory()
  else root.QRLite = factory()
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict'

  // 纠错等级：L=0, M=1, Q=2, H=3
  var ECL_ORD = { L: 0, M: 1, Q: 2, H: 3 }
  var ECL_FORMAT_BITS = [1, 0, 3, 2] // L, M, Q, H

  // 每块纠错码字数 [ecl][version]
  var ECC_CW_PER_BLOCK = [
    [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
  ]

  // 纠错块数量 [ecl][version]
  var NUM_EC_BLOCKS = [
    [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
  ]

  function getBit(x, i) {
    return ((x >>> i) & 1) !== 0
  }

  function numRawDataModules(ver) {
    var result = (16 * ver + 128) * ver + 64
    if (ver >= 2) {
      var numAlign = Math.floor(ver / 7) + 2
      result -= (25 * numAlign - 10) * numAlign - 55
      if (ver >= 7) result -= 36
    }
    return result
  }

  function numDataCodewords(ver, ecl) {
    return (
      Math.floor(numRawDataModules(ver) / 8) -
      ECC_CW_PER_BLOCK[ecl][ver] * NUM_EC_BLOCKS[ecl][ver]
    )
  }

  function utf8Bytes(text) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text)
    // 兜底实现（老环境）
    var out = []
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i)
      if (c < 0x80) out.push(c)
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
      else if (c >= 0xd800 && c < 0xdc00) {
        var c2 = text.charCodeAt(++i)
        var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00)
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63))
      } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    }
    return new Uint8Array(out)
  }

  // GF(256) 乘法，本原多项式 0x11D
  function gfMul(x, y) {
    var z = 0
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d)
      z ^= ((y >>> i) & 1) * x
    }
    return z & 0xff
  }

  function rsDivisor(degree) {
    var result = new Uint8Array(degree)
    result[degree - 1] = 1
    var root = 1
    for (var i = 0; i < degree; i++) {
      for (var j = 0; j < degree; j++) {
        result[j] = gfMul(result[j], root)
        if (j + 1 < degree) result[j] ^= result[j + 1]
      }
      root = gfMul(root, 0x02)
    }
    return result
  }

  function rsRemainder(data, divisor) {
    var result = new Uint8Array(divisor.length)
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ result[0]
      result.copyWithin(0, 1)
      result[result.length - 1] = 0
      for (var j = 0; j < result.length; j++) result[j] ^= gfMul(divisor[j], factor)
    }
    return result
  }

  /** 追加纠错码并按 QR 规则交织 */
  function addEccAndInterleave(data, ver, ecl) {
    var numBlocks = NUM_EC_BLOCKS[ecl][ver]
    var blockEccLen = ECC_CW_PER_BLOCK[ecl][ver]
    var rawCodewords = Math.floor(numRawDataModules(ver) / 8)
    var numShortBlocks = numBlocks - (rawCodewords % numBlocks)
    var shortBlockLen = Math.floor(rawCodewords / numBlocks)

    var datBlocks = []
    var eccBlocks = []
    var divisor = rsDivisor(blockEccLen)
    for (var i = 0, k = 0; i < numBlocks; i++) {
      var datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1)
      var dat = data.slice(k, k + datLen)
      k += datLen
      datBlocks.push(dat)
      eccBlocks.push(rsRemainder(dat, divisor))
    }

    var result = new Uint8Array(rawCodewords)
    var out = 0
    // 数据码字按列交织：短块在最后一列留空
    for (var col = 0; col < shortBlockLen - blockEccLen + 1; col++) {
      for (var b = 0; b < numBlocks; b++) {
        if (col < datBlocks[b].length) result[out++] = datBlocks[b][col]
      }
    }
    // 纠错码字按列交织：所有块长度一致
    for (var c2 = 0; c2 < blockEccLen; c2++) {
      for (var b2 = 0; b2 < numBlocks; b2++) result[out++] = eccBlocks[b2][c2]
    }
    return result
  }

  function Matrix(size) {
    this.size = size
    this.modules = new Uint8Array(size * size)
    this.isFunction = new Uint8Array(size * size)
  }
  Matrix.prototype.set = function (x, y, dark) {
    this.modules[y * this.size + x] = dark ? 1 : 0
  }
  Matrix.prototype.get = function (x, y) {
    return this.modules[y * this.size + x]
  }
  Matrix.prototype.setFn = function (x, y, dark) {
    this.modules[y * this.size + x] = dark ? 1 : 0
    this.isFunction[y * this.size + x] = 1
  }

  function alignmentPositions(ver, size) {
    if (ver === 1) return []
    var numAlign = Math.floor(ver / 7) + 2
    var step = Math.floor((ver * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2
    var result = [6]
    for (var pos = size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos)
    return result
  }

  function drawFunctionPatterns(m, ver, ecl) {
    var size = m.size
    for (var i = 0; i < size; i++) {
      m.setFn(6, i, i % 2 === 0)
      m.setFn(i, 6, i % 2 === 0)
    }
    // 三个定位图形（含分隔符）
    ;[[3, 3], [size - 4, 3], [3, size - 4]].forEach(function (p) {
      var cx = p[0], cy = p[1]
      for (var dy = -4; dy <= 4; dy++) {
        for (var dx = -4; dx <= 4; dx++) {
          var x = cx + dx, y = cy + dy
          if (x < 0 || y < 0 || x >= size || y >= size) continue
          var dist = Math.max(Math.abs(dx), Math.abs(dy))
          m.setFn(x, y, dist !== 2 && dist !== 4)
        }
      }
    })
    // 校正图形
    var align = alignmentPositions(ver, size)
    var n = align.length
    for (var a = 0; a < n; a++) {
      for (var b = 0; b < n; b++) {
        if ((a === 0 && b === 0) || (a === 0 && b === n - 1) || (a === n - 1 && b === 0)) continue
        for (var dy2 = -2; dy2 <= 2; dy2++) {
          for (var dx2 = -2; dx2 <= 2; dx2++) {
            m.setFn(align[a] + dx2, align[b] + dy2, Math.max(Math.abs(dx2), Math.abs(dy2)) !== 1)
          }
        }
      }
    }
    drawFormatBits(m, ecl, 0) // 先占位，选定掩码后再重写
    drawVersion(m, ver)
  }

  function drawFormatBits(m, ecl, mask) {
    var size = m.size
    var data = (ECL_FORMAT_BITS[ecl] << 3) | mask
    var rem = data
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    var bits = ((data << 10) | rem) ^ 0x5412

    for (var j = 0; j <= 5; j++) m.setFn(8, j, getBit(bits, j))
    m.setFn(8, 7, getBit(bits, 6))
    m.setFn(8, 8, getBit(bits, 7))
    m.setFn(7, 8, getBit(bits, 8))
    for (var k = 9; k < 15; k++) m.setFn(14 - k, 8, getBit(bits, k))

    for (var p = 0; p < 8; p++) m.setFn(size - 1 - p, 8, getBit(bits, p))
    for (var q = 8; q < 15; q++) m.setFn(8, size - 15 + q, getBit(bits, q))
    m.setFn(8, size - 8, true) // 固定深色模块
  }

  function drawVersion(m, ver) {
    if (ver < 7) return
    var size = m.size
    var rem = ver
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    var bits = (ver << 12) | rem
    for (var j = 0; j < 18; j++) {
      var bit = getBit(bits, j)
      var a = size - 11 + (j % 3)
      var b = Math.floor(j / 3)
      m.setFn(a, b, bit)
      m.setFn(b, a, bit)
    }
  }

  function drawCodewords(m, data) {
    var size = m.size
    var i = 0
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5
      for (var vert = 0; vert < size; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j
          var upward = ((right + 1) & 2) === 0
          var y = upward ? size - 1 - vert : vert
          if (!m.isFunction[y * size + x] && i < data.length * 8) {
            m.set(x, y, getBit(data[i >>> 3], 7 - (i & 7)))
            i++
          }
        }
      }
    }
  }

  function maskHit(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0
      case 1: return y % 2 === 0
      case 2: return x % 3 === 0
      case 3: return (x + y) % 3 === 0
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
      case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
    }
    return false
  }

  function applyMask(m, mask) {
    for (var y = 0; y < m.size; y++) {
      for (var x = 0; x < m.size; x++) {
        if (!m.isFunction[y * m.size + x] && maskHit(mask, x, y)) {
          m.modules[y * m.size + x] ^= 1
        }
      }
    }
  }

  function penalty(m) {
    var size = m.size
    var result = 0
    var x, y, run, color

    // 规则1：连续同色 >= 5
    for (y = 0; y < size; y++) {
      run = 1
      color = m.get(0, y)
      for (x = 1; x < size; x++) {
        if (m.get(x, y) === color) {
          run++
          if (run === 5) result += 3
          else if (run > 5) result++
        } else {
          color = m.get(x, y)
          run = 1
        }
      }
    }
    for (x = 0; x < size; x++) {
      run = 1
      color = m.get(x, 0)
      for (y = 1; y < size; y++) {
        if (m.get(x, y) === color) {
          run++
          if (run === 5) result += 3
          else if (run > 5) result++
        } else {
          color = m.get(x, y)
          run = 1
        }
      }
    }

    // 规则2：2x2 同色块
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var c = m.get(x, y)
        if (c === m.get(x + 1, y) && c === m.get(x, y + 1) && c === m.get(x + 1, y + 1)) result += 3
      }
    }

    // 规则3：类定位图形 1:1:3:1:1
    function finderLike(getter, len) {
      var score = 0
      for (var i = 0; i + 10 < len; i++) {
        var s = ''
        for (var k = 0; k < 11; k++) s += getter(i + k) ? '1' : '0'
        if (s === '10111010000' || s === '00001011101') score += 40
      }
      return score
    }
    for (y = 0; y < size; y++) {
      result += finderLike(function (i) { return m.get(i, y) }, size)
    }
    for (x = 0; x < size; x++) {
      result += finderLike(function (i) { return m.get(x, i) }, size)
    }

    // 规则4：深浅比例
    var dark = 0
    for (var i2 = 0; i2 < m.modules.length; i2++) dark += m.modules[i2]
    var total = size * size
    var k2 = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1
    result += k2 * 10

    return result
  }

  /**
   * 编码文本
   * @param {string} text
   * @param {string} [ecl='M'] L|M|Q|H
   * @returns {{size:number, modules:Uint8Array, version:number, mask:number}}
   */
  function encode(text, ecl, forceMask) {
    var level = ECL_ORD[(ecl || 'M').toUpperCase()]
    if (level === undefined) level = 1
    var bytes = utf8Bytes(text)

    // 选最小可用版本
    var ver = 0
    for (var v = 1; v <= 40; v++) {
      var ccBits = v <= 9 ? 8 : 16
      var need = 4 + ccBits + bytes.length * 8
      if (need <= numDataCodewords(v, level) * 8) {
        ver = v
        break
      }
    }
    if (!ver) throw new Error('内容过长，无法编码进二维码')

    // 位流：模式 + 字符数 + 数据
    var capacity = numDataCodewords(ver, level)
    var bits = []
    function push(value, len) {
      for (var i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1)
    }
    push(4, 4) // byte 模式
    push(bytes.length, ver <= 9 ? 8 : 16)
    for (var i = 0; i < bytes.length; i++) push(bytes[i], 8)

    // 终止符 + 补齐到字节
    var capacityBits = capacity * 8
    for (var t = 0; t < 4 && bits.length < capacityBits; t++) bits.push(0)
    while (bits.length % 8 !== 0) bits.push(0)

    var data = new Uint8Array(capacity)
    for (var b = 0; b < bits.length; b += 8) {
      var val = 0
      for (var k = 0; k < 8; k++) val = (val << 1) | bits[b + k]
      data[b / 8] = val
    }
    // 填充字节 0xEC / 0x11 交替
    for (var p = Math.ceil(bits.length / 8), pad = 0; p < capacity; p++, pad++) {
      data[p] = pad % 2 === 0 ? 0xec : 0x11
    }

    var allCodewords = addEccAndInterleave(data, ver, level)
    var size = ver * 4 + 17
    var m = new Matrix(size)
    drawFunctionPatterns(m, ver, level)
    drawCodewords(m, allCodewords)

    // 选罚分最低的掩码
    var best = 0
    if (typeof forceMask === 'number') {
      best = forceMask
    } else {
      var bestScore = Infinity
      for (var mask = 0; mask < 8; mask++) {
        applyMask(m, mask)
        drawFormatBits(m, level, mask)
        var score = penalty(m)
        if (score < bestScore) {
          bestScore = score
          best = mask
        }
        applyMask(m, mask) // 异或两次还原
      }
    }
    applyMask(m, best)
    drawFormatBits(m, level, best)

    return { size: size, modules: m.modules, version: ver, mask: best }
  }

  return { encode: encode }
})
