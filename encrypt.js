/**
 * RSA 加密工具: node encrypt.js <base64公钥> <要加密的文本>
 * 兼容 encryptlong(JSEncrypt.encryptLong): 长文本按 117 字符分段,
 * 每段 PKCS#1 v1.5 独立加密, 密文拼接后输出 base64
 */
const crypto = require('crypto');

const [pubKey, text] = process.argv.slice(2);
if (!pubKey || text === undefined) {
  console.error('用法: node encrypt.js <base64公钥> <要加密的文本>');
  process.exit(1);
}

const key = crypto.createPublicKey({
  key: Buffer.from(pubKey.replace(/\s+/g, ''), 'base64'),
  format: 'der',
  type: 'spki',
});
const keyBytes = Math.ceil(key.asymmetricKeyDetails.modulusLength / 8);
const maxBytes = keyBytes - 11; // PKCS#1 v1.5 填充占 11 字节

const chunks = text.length > maxBytes ? text.match(/.{1,117}/g) : [text];

try {
  const cipher = Buffer.concat(
    chunks.map((chunk) =>
      crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(chunk, 'utf8'))
    )
  );
  console.log(cipher.toString('base64'));
} catch (e) {
  console.error('加密失败: ' + e.message);
  process.exit(1);
}
