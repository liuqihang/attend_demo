/**
 * Node.js demo：对接后端 RSA 加密登录
 *
 * 后端关键点：
 *  - Hutool SecureUtil.rsa() 默认算法：RSA/ECB/PKCS1Padding
 *  - 公钥为 X.509(SubjectPublicKeyInfo) 的 Base64 字符串
 *  - 前端用公钥加密密码 -> Base64 密文，后端用私钥 PKCS1 解密
 *
 * 运行：node rsa-login-demo.node.js
 */

const crypto = require('crypto');

// ============ 配置区（按实际环境修改）============
const BASE_URL = 'https://xiaominapp.ccbft.com';                 // 后端地址
const CAPTCHA_API = '/smartoffice/oauth/service/oauth/captcha/getEncryptCaptchaInfo';       // 获取验证码+公钥的接口路径（按实际修改）
const LOGIN_API = '/smartoffice/oauth/service/oauth/loginByCaptchaEncrypt';         // 登录接口路径（OauthConstants.LOGIN_BY_CAPTCHA_ENCRYPT_URL，按实际修改）

// Basic Auth（对应 Postman Authorization -> Basic Auth）
const BASIC_AUTH_USERNAME = 'xiaomin_portal';
const BASIC_AUTH_PASSWORD = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjy5FgkzZgPQWEt8h+2BHPaUo0HUq9Ds3ef1VglzK14l5x9++wMqeM9OPaU4zbAcQcujNcUNPz3wzJCPrbEuf2rbiHRbT92eP7Faqd5SFvObAGBGSDx/FrHz2QG9esHtnflXPXoUJycOi+2+77O1vrrMGfePd1tMIyXCfXTvACxwIDAQAB';
const BASIC_AUTH_HEADER =
  'Basic ' + Buffer.from(`${BASIC_AUTH_USERNAME}:${BASIC_AUTH_PASSWORD}`, 'utf8').toString('base64');

// ============ 1. RSA 公钥加密（核心方法）============
/**
 * 用后端返回的 Base64 公钥加密明文
 * @param {string} plainText 明文（如密码）
 * @param {string} publicKeyBase64 后端 encryptKey 字段（X.509 Base64）
 * @returns {string} Base64 密文
 */
function rsaEncryptByPublicKey(plainText, publicKeyBase64) {
  // Hutool 的 getPublicKeyBase64() 是 X.509 DER 的 Base64，
  // Node 端用 spki 格式直接还原公钥对象
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyBase64, 'base64'),
    format: 'der',
    type: 'spki',
  });

  // RSA_PKCS1_PADDING 对应 Java 的 RSA/ECB/PKCS1Padding
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(plainText, 'utf8')
  );

  return encrypted.toString('base64');
}

// ============ 2. 完整登录流程 demo ============
async function login(username, password, validCode) {
  // 2.1 调 getEncryptCaptchaInfo 拿 captchaKey + 公钥 + 验证码图片
  const captchaRes = await fetch(BASE_URL + CAPTCHA_API, {
    headers: { Authorization: BASIC_AUTH_HEADER },
  });
  const captchaJson = await captchaRes.json();
  // 按后端实际响应结构调整，一般是 data 包裹
  const { captchaKey, encryptKey /*, imageBase64 */ } = captchaJson.data;

  console.log('captchaKey :', captchaKey);
  console.log('encryptKey :', encryptKey);

  // 2.2 用公钥加密密码
  const encryptedPassword = rsaEncryptByPublicKey(password, encryptKey);
  console.log('加密后密码 :', encryptedPassword);

  // 2.3 调 attemptAuthentication 对应的登录接口
  // 后端用的是 request.getParameter(...)，所以用 form-urlencoded 提交
  const body = new URLSearchParams({
    captchaKey,              // CAPTCHAKEY
    validCode,               // VALIDCODE：用户输入的验证码
    username,                // USERNAME
    password: encryptedPassword, // PASSWORD：RSA 加密后的 Base64 密文
  });

  const loginRes = await fetch(BASE_URL + LOGIN_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: BASIC_AUTH_HEADER,
    },
    body,
  });
  const loginJson = await loginRes.json();
  console.log('登录结果 :', loginJson);
  return loginJson;
}

// ============ 3. 本地自验证（不依赖后端，验证加解密可逆）============
function selfTest() {
  // 模拟后端 SecureUtil.rsa() 生成密钥对
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024, // Hutool 默认 1024
  });
  const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  const plain = 'MyP@ssw0rd123';
  const cipherB64 = rsaEncryptByPublicKey(plain, pubB64);
  console.log('[selfTest] 密文 Base64 :', cipherB64);

  // 模拟后端 decryptStr(password, KeyType.PrivateKey)
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(cipherB64, 'base64')
  );
  console.log('[selfTest] 解密结果 :', decrypted.toString('utf8'));
  console.log('[selfTest] 加解密一致 :', decrypted.toString('utf8') === plain);
}

// 入口：先跑自验证，再跑真实登录（取消注释并填入真实验证码）
selfTest();
// login('yourUsername', 'yourPassword', '验证码图片上的4位数字');
