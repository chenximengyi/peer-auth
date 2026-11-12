/* PeerAuth — 页面逻辑：生成密钥、画二维码、每秒刷新验证码 */
;(function () {
  'use strict'

  var ui = {
    name: document.getElementById('name'),
    generateForm: document.getElementById('generateForm'),
    generateBtn: document.getElementById('generateBtn'),
    generateError: document.getElementById('generateError'),
    qrSection: document.getElementById('qrSection'),
    canvas: document.getElementById('qrcode'),
    otpDisplay: document.getElementById('otpDisplay'),
    countdown: document.getElementById('countdown'),
    expiry: document.querySelector('.expiry'),
    secret: document.getElementById('secret')
  }

  var ISSUER = 'PeerAuth'
  var SECRET_BYTES = 32
  var PERIOD = 30
  var DIGITS = 6
  // 页面与二维码统一使用 SHA1，以兼容验证器的默认设置。
  var ALGORITHM = 'SHA1'

  var state = {
    secret: '',
    timer: null
  }

  // ---------- 二维码 ----------

  function drawQrCode(canvas, qr, targetPx) {
    var quiet = 4 // 静区 4 个模块，扫描器需要它
    var total = qr.size + quiet * 2
    var scale = Math.max(2, Math.round((targetPx || 260) / total))
    var px = total * scale

    canvas.width = px
    canvas.height = px
    // 只固定宽度，高度交给 CSS 的 height: auto 按画布比例推算，
    // 窄屏被 max-width 压缩时二维码才不会变形。
    canvas.style.width = px + 'px'

    var ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('Canvas 2D 不可用')
    ctx.fillStyle = '#ffffff'
    ctx.fillRect(0, 0, px, px)
    ctx.fillStyle = '#000000'

    for (var y = 0; y < qr.size; y++) {
      var x = 0
      while (x < qr.size) {
        if (qr.modules[y * qr.size + x]) {
          var run = 1
          while (x + run < qr.size && qr.modules[y * qr.size + x + run]) run++
          ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, run * scale, scale)
          x += run
        } else {
          x++
        }
      }
    }
  }

  function buildOtpAuthUri(name, secret) {
    return (
      'otpauth://totp/' +
      ISSUER +
      ':' +
      encodeURIComponent(name) +
      '?issuer=' +
      ISSUER +
      '&secret=' +
      secret +
      '&algorithm=' +
      ALGORITHM +
      '&digits=' +
      DIGITS +
      '&period=' +
      PERIOD
    )
  }

  // ---------- 验证码刷新 ----------

  function updateOtp() {
    var now = Date.now()
    ui.otpDisplay.textContent = TOTPLite.totp(state.secret, now, PERIOD, DIGITS, ALGORITHM)

    var remaining = PERIOD - (Math.floor(now / 1000) % PERIOD)
    ui.countdown.textContent = String(remaining)
    ui.expiry.classList.toggle('is-expiring', remaining <= 5)
  }

  function scheduleTick() {
    if (state.timer) clearTimeout(state.timer)
    state.timer = null
    if (!state.secret) return false
    try {
      updateOtp()
      // 对齐到整秒，避免倒计时慢半拍
      state.timer = setTimeout(scheduleTick, 1000 - (Date.now() % 1000) + 20)
      return true
    } catch (error) {
      abortGeneration('验证码更新失败，已停止生成。请重新生成或重新打开页面后再试。')
      return false
    }
  }

  // ---------- 事件 ----------

  function clearGeneration() {
    if (state.timer) clearTimeout(state.timer)
    state.timer = null
    state.secret = ''
    ui.qrSection.hidden = true
    ui.secret.textContent = ''
    ui.canvas.width = 0
    ui.canvas.height = 0
    ui.otpDisplay.textContent = '------'
    ui.countdown.textContent = String(PERIOD)
    ui.expiry.classList.toggle('is-expiring', false)
  }

  function abortGeneration(message) {
    clearGeneration()
    ui.generateError.hidden = false
    ui.generateError.textContent = message
  }

  function handleGenerate(event) {
    if (event) event.preventDefault()

    var name = ui.name.value.trim()
    if (!name) return

    ui.generateError.hidden = true
    ui.generateError.textContent = ''
    clearGeneration()
    var errorMessage = '无法获取安全随机数，已停止生成。请使用支持安全随机数的浏览器重新打开本地页面后再试。'
    try {
      var secret = TOTPLite.randomSecret(SECRET_BYTES)
      errorMessage = '生成失败，已停止生成。请重新输入名称后重试；若仍失败，请换用支持 Canvas 的浏览器。'
      var uri = buildOtpAuthUri(name, secret)
      var qr = QRLite.encode(uri, 'M')
      drawQrCode(ui.canvas, qr)

      state.secret = secret
      ui.secret.textContent = secret
      if (!scheduleTick()) return
      // 二维码和首个验证码都成功生成后，才展示配对结果。
      ui.qrSection.hidden = false
    } catch (error) {
      abortGeneration(errorMessage)
    }
  }

  function handleNameInput() {
    ui.generateBtn.disabled = ui.name.value.trim() === ''
  }

  function init() {
    ui.name.addEventListener('input', handleNameInput)
    ui.generateForm.addEventListener('submit', handleGenerate)
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && state.secret) scheduleTick()
    })
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init)
  else init()
})()
