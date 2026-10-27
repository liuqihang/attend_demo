/**
 * 手机验证码登录 + 手机打卡 demo 服务端（按 lxqy.md 实现）
 *
 * 功能：
 *  - 托管前端页面 public/login.html（登录）、public/app2.html（打卡）、public/app.html、public/index.html
 *  - 代理 3 个后端接口，解决浏览器跨域问题，Basic Auth 密钥不下发到浏览器
 *  - 提供 locationEncrypt 的 AES 加密接口（对应 java AES256Util.encode(key, content, iv)）
 *  - 手机号白名单拦截：白名单从 phone-whitelist.conf 实时读取（改完即生效，无需重启），
 *    非白名单手机号的请求输出控制台并追加写入 app_no_phone.log
 *
 * 运行：node attend-demo/server.js   然后浏览器访问 http://localhost:6960/lxqy/login.html
 * 依赖：无（Node 16+，仅用内置 http / https / crypto）
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ==================== 配置区 ====================
const PORT = 6960;
const BASE_PATH = '/lxqy';   // 页面访问前缀：http://localhost:6960/lxqy/app.html
const BASE_URL = 'https://xiaominweb.ccbft.com';
const SMS_CODE_API = '/smartoffice/oauth/service/oauth/sms/getSmsCode';          // 接口1 GET
const SMS_LOGIN_API = '/smartoffice/oauth/service/oauth/loginBySmsCode';         // 接口2 POST form-data
const ATTEND_API = '/smartoffice/attendservice/appattendservice/appattend/v3/addAppAttendRecord'; // 接口3 POST json

// 接口1、接口2 的 Basic Auth（对应 Postman Authorization -> Basic Auth）
const BASIC_AUTH_USERNAME = 'xiaomin_portal';
const BASIC_AUTH_PASSWORD = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjy5FgkzZgPQWEt8h+2BHPaUo0HUq9Ds3ef1VglzK14l5x9++wMqeM9OPaU4zbAcQcujNcUNPz3wzJCPrbEuf2rbiHRbT92eP7Faqd5SFvObAGBGSDx/FrHz2QG9esHtnflXPXoUJycOi+2+77O1vrrMGfePd1tMIyXCfXTvACxwIDAQAB';
const BASIC_AUTH_HEADER =
  'Basic ' + Buffer.from(`${BASIC_AUTH_USERNAME}:${BASIC_AUTH_PASSWORD}`, 'utf8').toString('base64');

// 接口3 Authorization 前缀。lxqy.md 描述为"直接取 accessToken 值"，默认不加前缀；
// 若接口返回 401，可尝试改为 'bearer '（接口2返回的 tokenType 是 bearer）
const TOKEN_PREFIX = '';

// locationEncrypt 密钥组成：s@_xtbg! + accessToken后4位 + tbUuid后4位
const LOCATION_KEY_PREFIX = 's@_xtbg!';

// 手机号白名单：从配置文件读取，每次校验都重新读取，改完立即生效（无需重启）
const PHONE_WHITELIST_FILE = path.join(__dirname, 'phone-whitelist.conf');
const DEFAULT_ALLOWED_PHONES = ['18900126960', '15926217640'];
const NO_PHONE_LOG = path.join(__dirname, 'app_no_phone.log');

// 上游请求超时（毫秒），便于定位网络不通/挂死问题
const UPSTREAM_TIMEOUT = 30000;

// 日志里单条内容的最大长度，超出截断（避免刷屏）
const LOG_MAX_LEN = 1200;

// ==================== 日志 ====================
function pad2(n, w = 2) { return String(n).padStart(w, '0'); }

function ts() {
  const d = new Date();
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} `
    + `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}.${pad2(d.getMilliseconds(), 3)}`;
}

// 普通日志 -> stdout（nohup 下写入 app.log）
function log(tag, msg) {
  console.log(`[${ts()}] [${tag}] ${msg}`);
}

// 错误日志 -> stderr（nohup 的 2>&1 也会合并进 app.log）
function logErr(tag, msg) {
  console.error(`[${ts()}] [${tag}] ${msg}`);
}

// 长字符串截断
function clip(v) {
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  if (s == null) return String(s);
  return s.length > LOG_MAX_LEN ? s.slice(0, LOG_MAX_LEN) + `...(共${s.length}字符)` : s;
}

// 敏感值脱敏：保留头部若干字符，便于定位前缀/长度问题
function mask(v, keep = 16) {
  const s = String(v == null ? '' : v);
  return s.length <= keep ? s : `${s.slice(0, keep)}...(${s.length}字符)`;
}

// ==================== 手机号白名单（配置文件实时读取） ====================
const WHITELIST_FILE_CONTENT = `# 手机打卡 Demo 手机号白名单
# 规则：一行一个手机号（也支持逗号/空格分隔）；# 之后为注释；空行忽略
# 修改保存后立即生效，无需重启服务
18900126960
15926217640
`;

// 首次运行时若配置文件不存在则按默认白名单生成
function ensureWhitelistFile() {
  try {
    if (!fs.existsSync(PHONE_WHITELIST_FILE)) {
      fs.writeFileSync(PHONE_WHITELIST_FILE, WHITELIST_FILE_CONTENT, 'utf8');
      log('PHONE', `白名单配置文件不存在，已生成默认配置: ${PHONE_WHITELIST_FILE}`);
    }
  } catch (e) {
    logErr('PHONE', `生成白名单配置文件失败: ${e.message}`);
  }
}

// 解析配置文件内容 -> 手机号数组（去重，忽略注释/空行/非法格式）
function loadAllowedPhones() {
  try {
    const text = fs.readFileSync(PHONE_WHITELIST_FILE, 'utf8');
    const tokens = [];
    text.split(/\r?\n/).forEach((line) => {
      line.split('#')[0]                       // 去掉行内注释
        .split(/[\s,;]+/)                      // 逗号/空格/分号分隔
        .forEach((t) => { if (t.trim()) tokens.push(t.trim()); });
    });
    const list = [];
    tokens.forEach((p) => {
      if (/^1\d{10}$/.test(p)) {
        if (!list.includes(p)) list.push(p);
      } else {
        logErr('PHONE', `白名单配置中忽略非法手机号: "${p}"`);
      }
    });
    return list.length ? list : DEFAULT_ALLOWED_PHONES.slice();
  } catch (e) {
    logErr('PHONE', `读取白名单配置失败(${e.message})，本次使用默认白名单`);
    return DEFAULT_ALLOWED_PHONES.slice();
  }
}

// 每次校验都重新读文件（实时生效）；仅在白名单发生变化时打印一次日志
let lastWhitelistSig = '';
function getAllowedPhones() {
  const list = loadAllowedPhones();
  const sig = list.join(',');
  if (sig !== lastWhitelistSig) {
    lastWhitelistSig = sig;
    log('PHONE', `白名单已加载(${list.length}个): ${list.join(', ')}`);
  }
  return list;
}

// ==================== 非白名单手机号拦截 ====================
/**
 * 拦截不支持手机号：控制台输出 + 追加写入 app_no_phone.log
 */
function rejectPhone(phone, req, pathname) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0].trim();
  const ua = req.headers['user-agent'] || '-';
  const detail = `拦截到不支持的手机号 phone=${phone || '(空)'} 接口=${pathname} IP=${ip} UA=${ua}`;

  logErr('PHONE✗', detail);   // 控制台输出（nohup 下同时会进 app.log）
  fs.appendFile(NO_PHONE_LOG, `[${ts()}] ${detail}\n`, (e) => {
    if (e) logErr('PHONE✗', `写入 app_no_phone.log 失败: ${e.message}`);
  });
}

// 手机号白名单校验，不通过则返回 true（已响应给浏览器）
function blockIfPhoneNotAllowed(phone, req, res, pathname) {
  const allowed = getAllowedPhones();
  if (allowed.includes(String(phone || ''))) return false;
  rejectPhone(phone, req, pathname);
  sendJson(res, 403, {
    error: 'PHONE_NOT_SUPPORTED',
    tip: `不支持该手机号：${phone || '(空)'}，仅支持 ${allowed.join('、')}`,
  });
  return true;
}

// ==================== AES 加密（对应 java AES256Util.encode） ====================
/**
 * 对应 java: AES256Util.encode(key, content, iv) —— AES/CBC/PKCS5Padding，key/iv 为原始字符串
 * key = iv = "s@_xtbg!" + accessToken后4位 + tbUuid后4位（共 16 字符）
 * 注意：Java 的 SecretKeySpec(16字节,"AES") 实际是 AES-128（尽管工具类名叫 AES256Util）。
 *       Node 端按 key 字节长度自动选择 aes-128/192/256-cbc，与 Java 行为一致。
 */
function aesEncode(keyStr, plainText, ivStr) {
  const key = Buffer.from(keyStr, 'utf8');
  const iv = Buffer.from(ivStr, 'utf8');
  const algo = { 16: 'aes-128-cbc', 24: 'aes-192-cbc', 32: 'aes-256-cbc' }[key.length];
  if (!algo) throw new Error(`密钥长度须为16/24/32字节，当前=${key.length}（${keyStr}）`);
  const cipher = crypto.createCipheriv(algo, key, iv);
  return Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]).toString('base64');
}

function buildLocationKey(accessToken, tbUuid) {
  return LOCATION_KEY_PREFIX + String(accessToken).slice(-4) + String(tbUuid).slice(-4);
}

// ==================== 工具函数 ====================
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj, null, 2));
}

function tryParse(text) {
  try { return JSON.parse(text); } catch { return text; }
}

// ==================== HTTP 请求 / form-data 组装（Node 16 无全局 fetch、FormData） ====================
/**
 * 通用 HTTP(S) 请求，返回 { status, text }
 */
function request(targetUrl, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const mod = u.protocol === 'https:' ? https : http;
    const startedAt = Date.now();

    log('HTTP→', `${method} ${targetUrl} (${body ? body.length : 0} bytes)`);

    const req = mod.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method,
      headers,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        log('HTTP←', `${method} ${targetUrl} -> ${res.statusCode} (${Date.now() - startedAt}ms) ${clip(text)}`);
        resolve({ status: res.statusCode, text });
      });
    });

    req.setTimeout(UPSTREAM_TIMEOUT, () => {
      req.destroy(new Error(`上游请求超时 ${UPSTREAM_TIMEOUT}ms`));
    });

    req.on('error', (e) => {
      logErr('HTTP✗', `${method} ${targetUrl} 请求失败 (${Date.now() - startedAt}ms): ${e.message}`);
      reject(e);
    });

    if (body) req.write(body);
    req.end();
  });
}

/**
 * 组装 multipart/form-data 请求体
 * @returns {{ boundary: string, payload: Buffer }}
 */
function buildFormData(fields) {
  const boundary = '----NodeDemoBoundary' + crypto.randomBytes(12).toString('hex');
  const parts = Object.entries(fields).map(([name, value]) => Buffer.from(
    `--${boundary}\r\n`
    + `Content-Disposition: form-data; name="${name}"\r\n\r\n`
    + `${value}\r\n`, 'utf8'));
  parts.push(Buffer.from(`--${boundary}--\r\n`, 'utf8'));
  return { boundary, payload: Buffer.concat(parts) };
}

// ==================== API 代理 ====================
async function handleApi(req, res, urlObj) {
  const p = urlObj.pathname;

  // 接口1：获取手机验证码 GET /api/getSmsCode?username=xxx
  if (p === '/api/getSmsCode' && req.method === 'GET') {
    const username = urlObj.searchParams.get('username') || '';
    log('SMS', `[接口1] 获取验证码 username=${username}`);
    // 手机号白名单校验：非白名单直接拦截并记录，不再请求上游
    if (blockIfPhoneNotAllowed(username, req, res, '/api/getSmsCode')) return;
    log('SMS', `[接口1] 上游 Authorization: ${mask(BASIC_AUTH_HEADER, 24)}`);
    const r = await request(BASE_URL + SMS_CODE_API + '?username=' + encodeURIComponent(username), {
      headers: { Authorization: BASIC_AUTH_HEADER },
    });
    return sendJson(res, 200, { upstreamStatus: r.status, body: tryParse(r.text) });
  }

  // 接口2：手机验证码登录 POST /api/loginBySmsCode  {phone, phoneCode, username}
  if (p === '/api/loginBySmsCode' && req.method === 'POST') {
    const { phone, phoneCode, username } = await readBody(req);
    log('LOGIN', `[接口2] 登录请求 phone=${phone} phoneCode=${phoneCode} username=${username}`);
    // 手机号白名单校验：非白名单直接拦截并记录，不再请求上游
    if (blockIfPhoneNotAllowed(phone, req, res, '/api/loginBySmsCode')) return;
    // 后端要求 form-data，手动组装 multipart 请求体
    const fields = { phone: phone || '', phoneCode: phoneCode || '', username: username || '' };
    const { boundary, payload } = buildFormData(fields);
    log('LOGIN', `[接口2] multipart 字段=${JSON.stringify(fields)} boundary=${boundary} 长度=${payload.length}`);
    const r = await request(BASE_URL + SMS_LOGIN_API, {
      method: 'POST',
      headers: {
        Authorization: BASIC_AUTH_HEADER,
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': payload.length,
      },
      body: payload,
    });
    return sendJson(res, 200, { upstreamStatus: r.status, body: tryParse(r.text) });
  }

  // locationEncrypt 加密 POST /api/encryptLocation  {accessToken, tbUuid, lat, lng}
  if (p === '/api/encryptLocation' && req.method === 'POST') {
    const { accessToken, tbUuid, lat, lng } = await readBody(req);
    log('CRYPT', `[加密] lat=${lat} lng=${lng} accessToken=${mask(accessToken)} tbUuid=${tbUuid}`);
    const key = buildLocationKey(accessToken, tbUuid);
    const content = `${lat}-${lng}`;
    const locationEncrypt = aesEncode(key, content, key);
    log('CRYPT', `[加密] key/iv=${key} (${Buffer.byteLength(key, 'utf8')}字节) 明文=${content}`);
    log('CRYPT', `[加密] locationEncrypt=${locationEncrypt}`);
    return sendJson(res, 200, { key, content, locationEncrypt });
  }

  // 接口3：手机打卡 POST /api/attend  {accessToken, body}
  if (p === '/api/attend' && req.method === 'POST') {
    const { accessToken, body } = await readBody(req);
    log('ATTEND', `[接口3] 打卡请求 accessToken=${mask(accessToken)}`);
    log('ATTEND', `[接口3] 打卡参数=${clip(body)}`);
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    log('ATTEND', `[接口3] Authorization 头=${mask(TOKEN_PREFIX + accessToken, 24)}`);
    const r = await request(BASE_URL + ATTEND_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length,
        Authorization: TOKEN_PREFIX + accessToken,
      },
      body: payload,
    });
    return sendJson(res, 200, { upstreamStatus: r.status, body: tryParse(r.text) });
  }

  logErr('API', `未匹配到接口 ${p}`);
  sendJson(res, 404, { error: 'not found: ' + p });
}

// ==================== 静态文件 + 路由 ====================
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, 'http://localhost');
  const startedAt = Date.now();
  const clientIp = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0].trim();

  // 每个请求的访问日志（含来源、方法、路径）
  log('REQ', `${req.method} ${req.url} from ${clientIp}`);

  // 请求结束时打印状态码与耗时
  res.on('finish', () => {
    log('RES', `${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - startedAt}ms)`);
  });

  try {
    // 去掉统一访问前缀 /lxqy（同时兼容不带前缀的根路径访问）
    const p = urlObj.pathname;
    if (p === BASE_PATH) urlObj.pathname = '/';
    else if (p.startsWith(BASE_PATH + '/')) urlObj.pathname = p.slice(BASE_PATH.length);

    if (urlObj.pathname.startsWith('/api/')) {
      return await handleApi(req, res, urlObj);
    }
    // 静态文件（仅 public 目录，防目录穿越）
    const filePath = path.join(PUBLIC_DIR, urlObj.pathname === '/' ? 'index.html' : urlObj.pathname);
    if (!filePath.startsWith(PUBLIC_DIR)) {
      logErr('STATIC', `越权访问被拒绝: ${urlObj.pathname}`);
      return sendJson(res, 403, { error: 'forbidden' });
    }
    if (!fs.existsSync(filePath)) {
      logErr('STATIC', `文件不存在: ${urlObj.pathname} (${filePath})`);
      return sendJson(res, 404, { error: 'not found: ' + urlObj.pathname });
    }
    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    log('STATIC', `返回文件 ${urlObj.pathname} (${content.length} bytes, ${ext || '无扩展名'})`);
    res.writeHead(200, { 'Content-Type': (MIME[ext] || 'application/octet-stream') + '; charset=utf-8' });
    res.end(content);
  } catch (e) {
    logErr('ERROR', `${req.method} ${req.url} 处理失败: ${(e && e.stack) || e}`);
    sendJson(res, 500, { error: String(e.message || e) });
  }
});

// 兜底异常日志，避免进程静默退出后无从定位
process.on('uncaughtException', (e) => logErr('FATAL', '未捕获异常: ' + ((e && e.stack) || e)));
process.on('unhandledRejection', (e) => logErr('FATAL', '未处理的 Promise 拒绝: ' + ((e && e.stack) || e)));

server.listen(PORT, () => {
  ensureWhitelistFile();
  log('BOOT', `入口页面: http://localhost:${PORT}${BASE_PATH}/login.html`);
  log('BOOT', `上游服务: ${BASE_URL}`);
  log('BOOT', `白名单配置: ${PHONE_WHITELIST_FILE}（实时读取，改完即生效）`);
  log('BOOT', `当前白名单: ${getAllowedPhones().join(', ')}`);
  log('BOOT', `进程 PID=${process.pid} | Node=${process.version} | 日志级别=全部`);
});
