/**
 * 命令行 RSA 加密测试工具
 *
 * 用法：
 *   node rsa-encrypt-cli.js <公钥Base64> <明文密码>
 *
 * 示例：
 *   node rsa-encrypt-cli.js "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjy5Fg..." "MyP@ssw0rd123"
 *
 * 输出：Base64 密文（可直接作为 password 参数传给登录接口）
 */

const crypto = require('crypto');

const [, , publicKeyBase64, plainText] = process.argv;

if (!publicKeyBase64 || !plainText) {
  console.error('用法: node rsa-encrypt-cli.js <公钥Base64> <明文密码>');
  process.exit(1);
}

const publicKey = crypto.createPublicKey({
  key: Buffer.from(publicKeyBase64, 'base64'),
  format: 'der',
  type: 'spki',
});

const encrypted = crypto.publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  Buffer.from(plainText, 'utf8')
);

console.log(encrypted.toString('base64'));
