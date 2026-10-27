/**
 * Windows 运行演示
 * 生成密钥对 -> 分别加密【短文本】和【超长文本(多段)】 -> 按块解密验证
 * 运行: node demo.js  (或直接双击 demo.bat)
 */
const crypto = require('crypto');
const { encryptLong, decryptLong } = require('./encrypt');

// 1. 生成 2048 位测试密钥对
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// 导出 base64(DER/SPKI) 公钥 —— 即实际业务传入 pubKey 的格式
const pubKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const privKeyPem = privateKey.export({ type: 'pkcs1', format: 'pem' });

const cases = [
  ['短文本', 'Hello, RSA! 你好，这是一段测试内容。'],
  ['长文本(>245字符, 触发 encryptLong 分段)', 'ABC123测试. '.repeat(40)],
];

console.log('========== RSA encryptLong 兼容加密演示 ==========');
console.log('\n公钥 (base64):');
console.log(pubKeyBase64);

let pass = true;
for (const [name, text] of cases) {
  console.log(`\n---- ${name} ----`);
  console.log('加密前 (' + text.length + ' 字符): ' + text.slice(0, 60) + (text.length > 60 ? '...' : ''));
  const cipher = encryptLong(pubKeyBase64, text);
  const blocks = Buffer.from(cipher, 'base64').length / 256;
  console.log('密文 base64 (' + blocks + ' 块): ' + cipher.slice(0, 60) + '...');
  const plain = decryptLong(privKeyPem, cipher);
  const ok = plain === text;
  pass = pass && ok;
  console.log('解密验证: ' + (ok ? '通过, 与原文一致' : '失败!'));
  if (!ok) console.log('  解密结果: ' + plain);
}

console.log('\n==================================================');
console.log(pass ? '全部验证通过: 输出与 encryptlong(JSEncrypt.encryptLong) 格式兼容 ✔' : '验证失败 ✘');
process.exit(pass ? 0 : 1);
