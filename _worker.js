import { connect } from 'cloudflare:sockets';

let p = 'dylj';
let fdc = [''];
let uid = '';
let yx = ['ip.sb', 'time.is', 'cdns.doon.eu.org'];
let dns = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';
let cpr = 'https://sublink.eooce.com/clash?config';
let spr = 'https://sublink.eooce.com/singbox?config';
const KC = 'cfip_list', KD = 'fdip_list', KP = 'admin_password', KU = 'user_uuid', KCp = 'clash_prefix', KSp = 'singbox_prefix';
const K_SETTINGS = 'SYSTEM_CONFIG';
let cc = null, ct = 0, CD = 60 * 1000;
const STALE_CD = 60 * 60 * 1000;
const MFS = 1000;
const dnsCache = new Map();
const serverHealthStats = new Map();
const loginAttempts = new Map();
const join = (...a) => a.join('');
const rand = () => Math.random();
const KS = 'user_sessions';
const SESSION_DURATION = 8 * 60 * 60 * 1000;
let ev = true;
let et = false;
let tp = '';
let protocolConfig = { ev, et, tp };
let globalTimeout = 5000;

const UUIDUtils = {
    generateStandardUUID() {
        return crypto.randomUUID();
    },
    generateSessionId() {
        return 'session_' + crypto.randomUUID() + Date.now().toString(36);
    },
    isValidUUID(uuid) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
    }
};

const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ipv6Regex = /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i;
const ipv6ShortRegex = /^::([0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}$/i;
const ipv6TrailingRegex = /^([0-9a-f]{1,4}:){1,7}:$/i;

const IPParser = {
    parsePreferredIP(input) {
        let hostname = input.trim();
        let port = 443;
        let countryName = '';
        let countryCode = '';
        let comment = '';
        if (hostname.includes('#')) {
            const parts = hostname.split('#');
            hostname = parts[0].trim();
            comment = parts[1].trim();
            if (comment.includes('|')) {
                const countryParts = comment.split('|');
                countryName = countryParts[0].trim();
                countryCode = countryParts[1]?.trim() || '';
            } else {
                countryName = comment;
            }
        }
        const { hostname: cleanHost, port: cleanPort } = this.parseConnectionAddress(hostname);
        return {
            hostname: cleanHost,
            port: cleanPort,
            countryName,
            countryCode,
            original: input,
            displayName: this.generateDisplayName(cleanHost, cleanPort, countryName, countryCode)
        };
    },
    parseConnectionAddress(input) {
        const defPort = 443;
        let hostname = input.trim();
        let port = defPort;
        if (hostname.includes('#')) {
            hostname = hostname.split('#')[0].trim();
        }
        if (hostname.includes('.tp')) {
            const match = hostname.match(/\.tp(\d+)\./);
            if (match) port = parseInt(match[1]);
        } else if (hostname.includes('[') && hostname.includes(']:')) {
            const portParts = hostname.split(']:');
            port = parseInt(portParts[1]);
            hostname = portParts[0] + ']';
        } else if (hostname.includes(':')) {
            const portParts = hostname.split(':');
            port = parseInt(portParts.pop());
            hostname = portParts.join(':');
        }
        return { hostname, port };
    },
    generateDisplayName(hostname, port, countryName, countryCode) {
        let displayName = hostname;
        if (countryCode) {
            const flag = getFlagEmoji(countryCode);
            displayName = `${flag} ${countryName} ${hostname}:${port}`;
        } else if (countryName) {
            displayName = `${countryName} ${hostname}:${port}`;
        } else if (port !== 443) {
            displayName = `${hostname}:${port}`;
        }
        return displayName;
    },
    isValidIP(ip) {
        const ipv4Match = ip.match(ipv4Regex);
        if (ipv4Match) {
            for (let i = 1; i <= 4; i++) {
                const num = parseInt(ipv4Match[i]);
                if (num < 0 || num > 255) return false;
            }
            return true;
        }
        if (ip.includes(':')) {
            return ipv6Regex.test(ip) || ipv6ShortRegex.test(ip) || ipv6TrailingRegex.test(ip);
        }
        if (ip.includes('.') && !ip.includes(' ')) {
            return true;
        }
        return false;
    }
};

const ResponseBuilder = {
    html(content, status = 200, extraHeaders = {}) {
        return new Response(content, {
            status,
            headers: {
                'Content-Type': 'text/html;charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...extraHeaders
            }
        });
    },
    text(content, status = 200, extraHeaders = {}) {
        return new Response(content, {
            status,
            headers: {
                'Content-Type': 'text/plain;charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...extraHeaders
            }
        });
    },
    json(data, status = 200, extraHeaders = {}) {
        return new Response(JSON.stringify(data), {
            status,
            headers: {
                'Content-Type': 'application/json;charset=utf-8',
                ...extraHeaders
            }
        });
    },
    redirect(url, status = 302, extraHeaders = {}) {
        return new Response(null, {
            status,
            headers: {
                'Location': url,
                ...extraHeaders
            }
        });
    }
};

const ConfigUtils = {
    async loadAllConfig(env) {
        const kv = env.SJ || env.sj;
        const defaultConfig = {
            yx: yx,
            fdc: fdc,
            uid: uid,
            cpr: cpr,
            spr: spr,
            ev: true,
            et: false,
            tp: '',
            klp: 'login',
            uuidSet: new Set(uid.split(',').map(s => s.trim())),
            cfConfig: {},
            proxyConfig: {}
        };

        if (!kv) return defaultConfig;

        try {
            const unifiedConfig = await kv.get(K_SETTINGS, 'json');
            if (unifiedConfig) {
                const configUid = unifiedConfig.uid || uid;
                return {
                    yx: unifiedConfig.yx || yx,
                    fdc: unifiedConfig.fdc || fdc,
                    uid: configUid,
                    cpr: unifiedConfig.cpr || cpr,
                    spr: unifiedConfig.spr || spr,
                    ev: unifiedConfig.protocolConfig?.ev ?? true,
                    et: unifiedConfig.protocolConfig?.et ?? false,
                    tp: unifiedConfig.protocolConfig?.tp ?? '',
                    cfConfig: unifiedConfig.cfConfig || {},
                    proxyConfig: unifiedConfig.proxyConfig || {},
                    klp: unifiedConfig.klp || 'login',
                    uuidSet: new Set(configUid.split(',').map(s => s.trim()))
                };
            }
        } catch (e) {}

        const keys = [KC, KD, KU, KCp, KSp, 'protocol_config', 'cf_config', 'proxy_config', 'custom_login_path'];
        const values = await Promise.all(keys.map(key => kv.get(key)));
        
        let protocolConfigFromKV = {};
        try {
            protocolConfigFromKV = values[5] ? JSON.parse(values[5]) : {};
        } catch (e) {
            protocolConfigFromKV = {};
        }
        let cfConfigFromKV = {};
        try {
            cfConfigFromKV = values[6] ? JSON.parse(values[6]) : {};
        } catch (e) {
            cfConfigFromKV = {};
        }
        let proxyConfigFromKV = {};
        try {
            proxyConfigFromKV = values[7] ? JSON.parse(values[7]) : {};
        } catch (e) {
            proxyConfigFromKV = {};
        }
        
        const configUid = values[2] || uid;
        return {
            yx: values[0] ? this.parseConfigValue(values[0]) : yx,
            fdc: values[1] ? this.parseConfigValue(values[1]) : fdc,
            uid: configUid,
            cpr: values[3] || cpr,
            spr: values[4] || spr,
            ev: protocolConfigFromKV.ev ?? true,
            et: protocolConfigFromKV.et ?? false,
            tp: protocolConfigFromKV.tp ?? '',
            cfConfig: cfConfigFromKV,
            proxyConfig: proxyConfigFromKV,
            klp: values[8] || 'login',
            uuidSet: new Set(configUid.split(',').map(s => s.trim()))
        };
    },
    parseConfigValue(value) {
        if (!value) return [];
        if (value.includes('\n')) {
            return value.split('\n').filter(Boolean);
        } else {
            return value.split(',').filter(Boolean);
        }
    }
};

const ErrorHandler = {
    internalError(message = 'Internal Server Error') {
        return ResponseBuilder.text(message, 500);
    },
    notFound(message = 'Not Found') {
        return ResponseBuilder.text(message, 404);
    },
    unauthorized(message = 'Unauthorized') {
        return ResponseBuilder.text(message, 401);
    },
    async safeExecute(operation, errorMessage = '操作失败') {
        try {
            return await operation();
        } catch (error) {
            return this.internalError(errorMessage);
        }
    }
};

function generateSessionId() {
    return UUIDUtils.generateSessionId();
}

async function saveSession(env, sessionId, userId) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    const sessionData = {
        userId: userId,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_DURATION
    };
    await kv.put(`${KS}:${sessionId}`, JSON.stringify(sessionData), { expirationTtl: 28800 });
    return true;
}

async function validateAndRefreshSession(env, sessionId) {
    const kv = env.SJ || env.sj;
    if (!kv) return { valid: false };
    const sessionData = await kv.get(`${KS}:${sessionId}`);
    if (!sessionData) return { valid: false };
    try {
        const session = JSON.parse(sessionData);
        const now = Date.now();
        if (now > session.expiresAt) {
            await kv.delete(`${KS}:${sessionId}`);
            return { valid: false };
        }
        const timeUntilExpiry = session.expiresAt - now;
        const refreshThreshold = 30 * 60 * 1000;
        if (timeUntilExpiry < refreshThreshold) {
            const newExpiresAt = now + SESSION_DURATION;
            session.expiresAt = newExpiresAt;
            await kv.put(
                `${KS}:${sessionId}`,
                JSON.stringify(session),
                { expirationTtl: 28800 }
            );
            return { valid: true, refreshed: true };
        }
        return { valid: true, refreshed: false };
    } catch {
        return { valid: false };
    }
}

async function deleteSession(env, sessionId) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.delete(`${KS}:${sessionId}`);
    return true;
}

function getSessionCookie(cookieHeader) {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'cf_worker_session' && value) {
            return value;
        }
    }
    return null;
}

function setSessionCookie(sessionId) {
    const expires = new Date(Date.now() + SESSION_DURATION).toUTCString();
    return `cf_worker_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${expires}`;
}

function clearSessionCookie() {
    return `cf_worker_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

async function requireAuth(req, env, handler) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) {
        return getPoemPage();
    }
    if (sessionResult.refreshed) {
        const response = await handler(req, env);
        response.headers.set('Set-Cookie', setSessionCookie(sessionId));
        return response;
    }
    return handler(req, env);
}

async function handleLogin(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const url = new URL(req.url);
    const passwordChanged = url.searchParams.get('password_changed') === 'true';
    const clientIp = req.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();

    if (loginAttempts.size > 1000) loginAttempts.clear();
    const attempt = loginAttempts.get(clientIp) || { count: 0, time: 0 };
    
    if (attempt.count > 5 && (now - attempt.time) < 60000) {
        return ResponseBuilder.text('尝试次数过多，请稍后再试', 429);
    }

    if (req.method === 'POST') {
        const form = await req.formData();
        const password = form.get('password');
        const storedPassword = await gP(env);
        if (password === storedPassword) {
            loginAttempts.delete(clientIp);
            const sessionId = generateSessionId();
            await saveSession(env, sessionId, 'admin');
            const response = await getMainPageContent(host, base, storedPassword, await gU(env), env);
            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
            return response;
        } else {
            loginAttempts.set(clientIp, { count: attempt.count + 1, time: now });
            return getLoginPage(host, base, true, false);
        }
    } else {
        return getLoginPage(host, base, false, passwordChanged);
    }
}

async function handleLogout(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    if (sessionId) {
        await deleteSession(env, sessionId);
    }
    return ResponseBuilder.redirect(`${base}/`, 302, {
        'Set-Cookie': clearSessionCookie()
    });
}

async function optimizeConfigLoading(env, ctx) {
    if (env.CONNECT_TIMEOUT) {
        globalTimeout = parseInt(env.CONNECT_TIMEOUT) || 5000;
    }
    const now = Date.now();
    if (cc && (now - ct) < CD) {
        return cc;
    }
    
    const loadConfigTask = async () => {
        try {
            const config = await ConfigUtils.loadAllConfig(env);
            const newConfig = {
                ...config,
                timestamp: now,
                parsedIPs: config.yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: config.fdc.filter(s => s && s.trim() !== '')
            };
            cc = newConfig;
            ct = now;
            yx = cc.yx;
            fdc = cc.fdc;
            uid = cc.uid;
            cpr = cc.cpr;
            spr = cc.spr;
            ev = cc.ev;
            et = cc.et;
            tp = cc.tp;
            protocolConfig = { ev, et, tp };
            return cc;
        } catch (error) {
            if (cc) return cc;
            return {
                yx: yx,
                fdc: fdc,
                uid: uid,
                cpr: cpr,
                spr: spr,
                ev: ev,
                et: et,
                tp: tp,
                parsedIPs: yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: fdc.filter(s => s && s.trim() !== ''),
                uuidSet: new Set(uid.split(',').map(s => s.trim())),
                proxyConfig: {}
            };
        }
    };

    if (cc && (now - ct) < STALE_CD && ctx) {
        ctx.waitUntil(loadConfigTask().catch(console.error));
        return cc;
    }

    return await loadConfigTask();
}

async function ldCfg(env, ctx) {
    return await optimizeConfigLoading(env, ctx);
}

async function gP(env) {
    const kv = env.SJ || env.sj;
    return kv ? await kv.get(KP) : null;
}

async function gU(env) {
    const kv = env.SJ || env.sj;
    return kv ? await kv.get(KU) : null;
}

async function sP(env, pw) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KP, pw);
    return true;
}

async function sU(env, u) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KU, u);
    return true;
}

async function saveConfigToKV(env, cfipArr, fdipArr, u = null, protocolCfg = null, cfCfg = null, proxyCfg = null, klp = null) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;

    const unifiedConfig = {
        yx: cfipArr,
        fdc: fdipArr,
        uid: u || uid,
        cpr: cpr,
        spr: spr,
        protocolConfig: protocolCfg || { ev, et, tp },
        cfConfig: cfCfg || {},
        proxyConfig: proxyCfg || {},
        klp: klp || 'login'
    };

    const ps = [
        kv.put(K_SETTINGS, JSON.stringify(unifiedConfig))
    ];

    if (u) ps.push(kv.put(KU, u));

    await Promise.all(ps);

    const uuidSet = new Set((u || uid).split(',').map(s => s.trim()));
    cc = {
        ...unifiedConfig,
        timestamp: Date.now(),
        ev: unifiedConfig.protocolConfig.ev,
        et: unifiedConfig.protocolConfig.et,
        tp: unifiedConfig.protocolConfig.tp,
        parsedIPs: cfipArr.map(ip => IPParser.parsePreferredIP(ip)),
        validFDCs: fdipArr.filter(s => s && s.trim() !== ''),
        uuidSet: uuidSet
    };
    ct = Date.now();
    return true;
}

async function savePrefixConfigToKV(env, clashP, singP) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    
    try {
        let currentConfig = await kv.get(K_SETTINGS, 'json');
        if (!currentConfig) {
            const loaded = await ConfigUtils.loadAllConfig(env);
            currentConfig = {
                yx: loaded.yx,
                fdc: loaded.fdc,
                uid: loaded.uid,
                cpr: clashP,
                spr: singP,
                protocolConfig: { ev: loaded.ev, et: loaded.et, tp: loaded.tp },
                cfConfig: loaded.cfConfig,
                proxyConfig: loaded.proxyConfig,
                klp: loaded.klp
            };
        } else {
            currentConfig.cpr = clashP;
            currentConfig.spr = singP;
        }
        
        await kv.put(K_SETTINGS, JSON.stringify(currentConfig));
        
        if (cc) {
            cc.cpr = clashP;
            cc.spr = singP;
        }
        return true;
    } catch (e) {
        return false;
    }
}

async function optimizedResolveHostname(hostname) {
    if (IPParser.isValidIP(hostname)) {
        return hostname;
    }
    const now = Date.now();
    if (dnsCache.size > 500) {
        const oldestKey = dnsCache.keys().next().value;
        dnsCache.delete(oldestKey);
    }
    const cached = dnsCache.get(hostname);
    if (cached) {
        const cacheTime = 5 * 60 * 1000;
        if (now - cached.timestamp < cacheTime) {
            return cached.ip;
        }
    }
    try {
        const ip = await resolveHostname(hostname);
        dnsCache.set(hostname, {
            ip,
            timestamp: now,
            success: true
        });
        return ip;
    } catch (error) {
        dnsCache.set(hostname, {
            ip: hostname,
            timestamp: now,
            success: false
        });
        return hostname;
    }
}

async function resolveHostname(h) {
    if (IPParser.isValidIP(h)) {
        return h;
    }
    const now = Date.now();
    const cached = dnsCache.get(h);
    if (cached && (now - cached.ts) < 5 * 60 * 1000) {
        return cached.ip;
    }
    const providers = [
        dns,
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve'
    ];
    const fetchDNS = async (provider) => {
        const url = `${provider}?name=${h}&type=A`;
        const res = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });
        if (res.ok) {
            const data = await res.json();
            if (data.Answer?.length > 0) {
                return data.Answer[0].data;
            }
        }
        throw new Error('No record');
    };
    try {
        const ip = await Promise.any(providers.map(p => fetchDNS(p)));
        dnsCache.set(h, { ip, ts: now });
        return ip;
    } catch {
        return h;
    }
}

async function universalConnectWithFailover() {
    if (serverHealthStats.size > 100) serverHealthStats.clear();
    
    const valid = fdc.filter(s => s && s.trim() !== '');
    const all = [...valid];
    if (all.length === 0) all.push('Kr.tp50000.netlib.re');
    
    const sorted = all.sort((a, b) => {
        const scoreA = serverHealthStats.get(a) || 0;
        const scoreB = serverHealthStats.get(b) || 0;
        if (scoreA === scoreB) return 0.5 - Math.random();
        return scoreB - scoreA;
    });

    const candidates = sorted.slice(0, 3);

    const tryConnect = async (s) => {
        const { hostname, port } = IPParser.parseConnectionAddress(s);
        const rh = await optimizedResolveHostname(hostname);
        const socket = await connect({ 
            hostname: rh, 
            port: port, 
            connectTimeout: globalTimeout,
            allowHalfOpen: true 
        });
        serverHealthStats.set(s, (serverHealthStats.get(s) || 0) + 1);
        return { socket, server: { hostname: rh, port: port, original: s } };
    };

    try {
        return await tryConnect(candidates[0]);
    } catch (e) {
        serverHealthStats.set(candidates[0], (serverHealthStats.get(candidates[0]) || 0) - 2);
        
        if (candidates.length > 1) {
            const remaining = candidates.slice(1);
            try {
                return await Promise.any(remaining.map(s => tryConnect(s).catch(err => {
                    serverHealthStats.set(s, (serverHealthStats.get(s) || 0) - 2);
                    throw err;
                })));
            } catch (err) {
                throw new Error('All connections failed');
            }
        }
        throw e;
    }
}

function obfuscateUserAgent() {
    const uas = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
    ];
    return uas[Math.floor(rand() * uas.length)];
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (e) { }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
async function sha224Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    padded[msgLen] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen, false);
    for (let chunk = 0; chunk < paddedLen; chunk += 64) {
        const W = new Uint32Array(64);
        for (let i = 0; i < 16; i++) {
            W[i] = view.getUint32(chunk + i * 4, false);
        }

        for (let i = 16; i < 64; i++) {
            const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }

        let [a, b, c, d, e, f, g, h] = H;
        for (let i = 0; i < 64; i++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    const result = [];
    for (let i = 0; i < 7; i++) {
        result.push(
            ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
            (H[i] & 0xff).toString(16).padStart(2, '0')
        );
    }

    return result.join('');
}

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

async function parseTrojanHeader(buffer, ut) {
    const passwordToHash = tp || ut;
    const sha224Password = await sha224Hash(passwordToHash);
    if (buffer.byteLength < 58) {
        return {
            hasError: true,
            message: "invalid trojan data - too short"
        };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer)[crLfIndex] !== 0x0d ||
        new Uint8Array(buffer)[crLfIndex + 1] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid trojan header format (missing CR LF)"
        };
    }
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) {
        return {
            hasError: true,
            message: "invalid trojan password"
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data"
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed"
        };
    }

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + 1)
            )[0];
            addressIndex += 1;
            address = new TextDecoder().decode(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    return {
        hasError: false,
        addressRemote: address,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

async function VLOverWSHandler(req, config, proxyCtx) {
    const webSocketPair = new WebSocketPair();
    const [client, ws] = Object.values(webSocketPair);
    ws.accept();
    const early = req.headers.get('sec-websocket-protocol') || '';
    const stream = makeReadableWebSocketStream(ws, early);
    let remote = { value: null };
    let udpWrite = null;
    let isDns = false;
    let protocolType = null;
    let processed = false;

    let remoteWriter = null;

    stream.pipeTo(new WritableStream({
        async write(chunk, ctrl) {
            try {
                if (processed) {
                    if (isDns && udpWrite) {
                        return udpWrite(chunk);
                    }
                    if (remote.value) {
                        if (!remoteWriter) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        await remoteWriter.write(chunk);
                        return;
                    }
                    return;
                }

                let protocolDetected = false;

                if (et && !protocolDetected) {
                    const tjResult = await parseTrojanHeader(chunk, uid);
                    if (!tjResult.hasError) {
                        protocolType = 'trojan';
                        protocolDetected = true;
                        const { addressRemote, port, rawClientData } = tjResult;
                        await handleTCP(remote, addressRemote, port, rawClientData, ws, null, proxyCtx);
                        if (remote.value) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        processed = true;
                        return;
                    }
                }

                if (ev && !protocolDetected) {
                    const vlessResult = await processVHeader(chunk, config.uuidSet);
                    if (!vlessResult.hasError) {
                        protocolType = 'vless';
                        protocolDetected = true;
                        const { portRemote, addressRemote, rawDataIndex, VLVersion, isUDP } = vlessResult;
                        if (isUDP) {
                            if (portRemote === 53) isDns = true;
                            else throw new Error('UDP proxy only enable for DNS which is port 53');
                        }
                        const respHeader = new Uint8Array([VLVersion[0], 0]);
                        const rawData = chunk.slice(rawDataIndex);
                        
                        if (isDns) {
                            const { write } = await handleUDPO(ws, respHeader);
                            udpWrite = write;
                            udpWrite(rawData);
                            processed = true;
                            return;
                        }
                        
                        await handleTCP(remote, addressRemote, portRemote, rawData, ws, respHeader, proxyCtx);
                        if (remote.value) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        processed = true;
                        return;
                    }
                }

                if (!protocolDetected) {
                    throw new Error('Invalid protocol');
                }

            } catch (e) {
                if (remoteWriter) {
                    try { await remoteWriter.close(); } catch(err) {}
                    remoteWriter = null;
                }
                ctrl.error(e);
            }
        },
        close() {
            if (remoteWriter) {
                try { remoteWriter.close(); } catch(e) {}
            }
        },
        abort(r) {
            if (remoteWriter) {
                try { remoteWriter.abort(r); } catch(e) {}
            }
        },
    })).catch((err) => {
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function handleTCP(remote, addr, pt, raw, ws, vh, proxyCtx) {
    const tcpSocket = await createConnection(addr, pt, proxyCtx);
    remote.value = tcpSocket;
    
    if (vh) {
        if (ws.readyState === WS_READY_STATE_OPEN) {
            ws.send(vh);
        }
    }
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(raw);
    writer.releaseLock();

    tcpSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (ws.readyState === WS_READY_STATE_OPEN) {
                ws.send(chunk);
            }
        },
        close() {
            safeCloseWebSocket(ws);
        },
        abort() {
            safeCloseWebSocket(ws);
        }
    })).catch(() => {
        safeCloseWebSocket(ws);
    });
    
    return;
}

async function createConnection(host, port, proxyCtx, addressType = 3) {
    async function useSocks5Pattern(address, whitelist) {
        if (!whitelist || whitelist.length === 0) return false;
        
        const targetHost = address.toLowerCase();
        
        return whitelist.some(pattern => {
            const p = pattern.trim().toLowerCase();
            if (!p) return false;

            if (p === '*') return true;

            if (p.includes('*') || p.includes('?')) {
                const escapeRegex = (str) => str.replace(/[.+^${}()|[\]\\]/g, '\\$&');
                const regexString = '^' + escapeRegex(p).replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
                try {
                    return new RegExp(regexString).test(targetHost);
                } catch (e) {
                    return false;
                }
            }
            
            if (targetHost === p || targetHost.endsWith('.' + p)) {
                return true;
            }
            
            return false;
        });
    }

    const { enableType, global, whitelist, parsedAddress } = proxyCtx;
    let shouldUseProxy = global;
    
    if (!shouldUseProxy && enableType) {
        shouldUseProxy = await useSocks5Pattern(host, whitelist);
    }

    let sock = null;

    if (shouldUseProxy && enableType) {
        try {
            if (enableType === 'socks5') {
                sock = await socks5Connect(host, port, parsedAddress, addressType);
            } else if (enableType === 'http') {
                sock = await httpConnect(host, port, parsedAddress);
            }
        } catch (e) {
        }
    }

    if (!sock) {
        try {
            sock = connect({ 
                hostname: host, 
                port, 
                connectTimeout: globalTimeout,
                allowHalfOpen: true
            });
            await sock.opened;
        } catch (e) {
            sock = null;
        }
    }

    if (!sock) {
        try {
            const { socket } = await universalConnectWithFailover();
            sock = socket;
        } catch (failoverErr) {
            throw new Error(`连接失败: 代/直/反均不可用. 目标: ${host}:${port}`);
        }
    }

    return sock;
}

async function socks5Connect(addressRemote, portRemote, proxyAddress, addressType = 3) {
    const { username, password, hostname, port } = proxyAddress;
    const socket = connect({ 
        hostname, 
        port, 
        connectTimeout: globalTimeout,
        allowHalfOpen: true
    });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read()).value;
    if (res[0] !== 0x05 || res[1] === 0xff) return;
    if (res[1] === 0x02) {
        if (!username || !password) return;
        await writer.write(new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]));
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) return;
    }

    const DSTADDR = addressType === 1 ?
        new Uint8Array([1, ...addressRemote.split('.').map(Number)])
        : addressType === 3 ?
            new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)])
            : new Uint8Array([4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
    await writer.write(new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]));
    res = (await reader.read()).value;
    if (res[1] !== 0x00) return;

    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

async function httpConnect(addressRemote, portRemote, proxyAddress) {
    const { username, password, hostname, port } = proxyAddress;
    const sock = await connect({ 
        hostname, 
        port, 
        connectTimeout: globalTimeout,
        allowHalfOpen: true
    });
    const authHeader = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
    const connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n` +
        `Host: ${addressRemote}:${portRemote}\r\n` +
        authHeader +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n` +
        `Proxy-Connection: Keep-Alive\r\n` +
        `Connection: Keep-Alive\r\n\r\n`;
    const writer = sock.writable.getWriter();
    try {
        await writer.write(new TextEncoder().encode(connectRequest));
    } catch (err) {
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    } finally {
        writer.releaseLock();
    }
    const reader = sock.readable.getReader();
    let responseBuffer = new Uint8Array(0);
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP代理连接中断');
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            const respText = new TextDecoder().decode(responseBuffer);
            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                if (!headers.startsWith('HTTP/1.1 200') && !headers.startsWith('HTTP/1.0 200')) {
                    throw new Error(`HTTP代理连接失败: ${headers.split('\r\n')[0]}`);
                }
                if (headersEndPos < responseBuffer.length) {
                    const remainingData = responseBuffer.slice(headersEndPos);
                    const { readable, writable } = new TransformStream();
                    new ReadableStream({
                        start(controller) {
                            controller.enqueue(remainingData);
                        }

                    }).pipeTo(writable).catch(() => { });
                    sock.readable = readable;
                }
                break;
            }
        }
    } catch (err) {
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    } finally {
        reader.releaseLock();
    }
    return sock;
}

function makeReadableWebSocketStream(ws, early) {
    let cancel = false;
    const stream = new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', (e) => {
                if (cancel) return;
                ctrl.enqueue(e.data);
            });
            ws.addEventListener('close', () => {

                safeCloseWebSocket(ws);
                if (cancel) return;
                ctrl.close();
            });
            ws.addEventListener('error', (e) => {
                ctrl.error(e);
            });

            const { earlyData, error } = base64ToArrayBuffer(early);
            if (error) {
                ctrl.error(error);
            } else if (earlyData) {
                ctrl.enqueue(earlyData);
            }
        },

        pull(ctrl) { },
        cancel() {
            cancel = true;
            safeCloseWebSocket(ws);
        }
    });
    return stream;
}

async function processVHeader(VLBuffer, uuidSet) {
    if (VLBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }
    const version = new Uint8Array(VLBuffer.slice(0, 1));
    let isValid = false;
    let isUDP = false;
    const slice = new Uint8Array(VLBuffer.slice(1, 17));
    const sliceStr = stringify(slice);
    
    isValid = uuidSet ? uuidSet.has(sliceStr) : (sliceStr === uid);

    if (!isValid) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }
    const optLen = new Uint8Array(VLBuffer.slice(17, 18))[0];
    const cmd = new Uint8Array(VLBuffer.slice(18 + optLen, 18 + optLen + 1))[0];
    if (cmd === 2) {
        isUDP = true;
    } else if (cmd !== 1) {
        return {
            hasError: true,
            message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLen + 1;
    const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addrIndex = portIndex + 2;
    const addrBuffer = new Uint8Array(VLBuffer.slice(addrIndex, addrIndex + 1));
    const addrType = addrBuffer[0];
    let addrLen = 0;
    let addrValIndex = addrIndex + 1;
    let addrVal = '';
    switch (addrType) {
        case 1:
            addrLen = 4;
            addrVal = new Uint8Array(VLBuffer.slice(addrValIndex, addrValIndex + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(VLBuffer.slice(addrValIndex, addrValIndex + 1))[0];
            addrValIndex += 1;
            addrVal = new TextDecoder().decode(VLBuffer.slice(addrValIndex, addrValIndex + addrLen));
            break;
        case 3:
            addrLen = 16;
            const dv = new DataView(VLBuffer.slice(addrValIndex, addrValIndex + addrLen));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dv.getUint16(i * 2).toString(16));
            }
            addrVal = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${addrType}`,
            };
    }
    if (!addrVal) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addrType}`,
        };
    }
    return {
        hasError: false,
        addressRemote: addrVal,
        addressType: addrType,
        portRemote: portRemote,
        rawDataIndex: addrValIndex + addrLen,
        VLVersion: version,
        isUDP: isUDP,
    };
}

function isValidAUTH(id) {
    const reg = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return reg.test(id);
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
    const id = unsafeStringify(arr, offset);
    if (!isValidAUTH(id)) {
        throw TypeError("Stringified id is invalid");
    }
    return id;
}

async function handleUDPO(ws, vh) {
    if (vh) {
        if (ws.readyState === WS_READY_STATE_OPEN) {
            ws.send(vh);
        }
    }

    const ts = new TransformStream({
        transform(chunk, ctrl) {
            for (let i = 0; i < chunk.byteLength;) {
                const lenBuf = chunk.slice(i, i + 2);
                const len = new DataView(lenBuf).getUint16(0);
                const
                    data = new Uint8Array(chunk.slice(i + 2, i + 2 + len));
                i = i + 2 + len;
                ctrl.enqueue({ lenBuf, data });
            }
        },
    });
    ts.readable.pipeTo(new WritableStream({
        async write({ lenBuf, data }) {
            const res = await fetch(dns, {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: data,
            });

            const ans = await res.arrayBuffer();
            const sz = ans.byteLength;
            const szBuf = new Uint8Array([(sz >> 8) & 0xff, sz & 0xff]);

            const responseData = new Uint8Array(szBuf.byteLength + ans.byteLength);
            responseData.set(szBuf, 0);

            responseData.set(new Uint8Array(ans), szBuf.byteLength);

            if (ws.readyState === WS_READY_STATE_OPEN) {
                ws.send(responseData);
            }
        }
    })).catch(() => { });
    const w = ts.writable.getWriter();
    return {
        write(chunk) {
            w.write(chunk);
        }
    };
}

function getFlagEmoji(c) {
    if (!c || c.length !== 2) return '';
    const cp = c.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...cp);
}

function genConfig(u, url) {
    if (!u) return '';
    const wp = '/?ed=2560';
    const ep = encodeURIComponent(wp);
    const links = [];

    if (ev) {
        const hd = join('v', 'l', 'e', 's', 's');
        const vlessLinks = yx.map(item => {
            const { hostname, port, displayName } = IPParser.parsePreferredIP(item);
            return `${hd}://${u}@${hostname}:${port}?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}#${encodeURIComponent('Vless-' + displayName)}`;
        });
        links.push(...vlessLinks);
    }

    if (et) {
        const password = tp || u;
        const trojanLinks = yx.map(item => {
            const { hostname, port, displayName } = IPParser.parsePreferredIP(item);
            const hd = join('t', 'r', 'o', 'j', 'a', 'n');
            return `${hd}://${password}@${hostname}:${port}?security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}#${encodeURIComponent('Trojan-' + displayName)}`;
        });
        links.push(...trojanLinks);
    }

    if (links.length === 0) {
        const hd = join('v', 'l', 'e', 's', 's');
        const vlessLinks = yx.map(item => {
            const { hostname, port, displayName } = IPParser.parsePreferredIP(item);
            return `${hd}://${u}@${hostname}:${port}?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}#${encodeURIComponent(displayName)}`;
        });
        links.push(...vlessLinks);
    }

    const finalConfig = links.join('\n')
        .replace(new RegExp(join('v', 'l', 'e', 's', 's'), 'g'), 'vless')
        .replace(new RegExp(join('t', 'r', 'o', 'j', 'a', 'n'), 'g'), 'trojan');
    return finalConfig;
}

async function getCloudflareUsage(env) {
    if (!cc?.cfConfig) return { success: false, pages: 0, workers: 0, total: 0 };
    const { apiMode, accountId, apiToken, email, globalApiKey } = cc.cfConfig;
    if (!accountId || (!apiToken && (!email || !globalApiKey))) {
        return { success: false, pages: 0, workers: 0, total: 0 };
    }

    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    const cfg = { "Content-Type": "application/json" };

    try {
        let AccountID = accountId;
        if (!AccountID && apiMode === 'email') {
            const r = await fetch(`${API}/accounts`, {
                method: "GET",
                headers: { ...cfg, "X-AUTH-EMAIL": email, "X-AUTH-KEY": globalApiKey }
            });
            if (!r.ok) return { success: false, pages: 0, workers: 0, total: 0 };
            const d = await r.json();
            if (!d?.result?.length) return { success: false, pages: 0, workers: 0, total: 0 };
            const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(email.toLowerCase()));
            AccountID = d.result[idx >= 0 ? idx : 0]?.id;
        }

        const now = new Date();
        now.setUTCHours(0, 0, 0, 0);
        const hdr = apiMode === 'token' ?
            { ...cfg, "Authorization": `Bearer ${apiToken}` } : { ...cfg, "X-AUTH-EMAIL": email, "X-AUTH-KEY": globalApiKey };
        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: hdr,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
         
                pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,

                variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
            })
        });
        if (!res.ok) return { success: false, pages: 0, workers: 0, total: 0 };
        const result = await res.json();
        if (result.errors?.length) return { success: false, pages: 0, workers: 0, total: 0 };

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) return { success: false, pages: 0, workers: 0, total: 0 };

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;

        return { success: true, pages, workers, total };
    } catch (error) {
        return { success: false, pages: 0, workers: 0, total: 0 };
    }
}

async function getRequestProxyConfig(request, config) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    let proxyCtx = {
        enableType: config.proxyConfig?.enabled ? config.proxyConfig.type : null,
        global: config.proxyConfig?.global || false,
        account: config.proxyConfig?.account || '',
        whitelist: config.proxyConfig?.whitelist || ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'],
        parsedAddress: {}
    };

    let tempAccount = searchParams.get('socks5') || searchParams.get('http') || proxyCtx.account;
    if (searchParams.has('globalproxy')) proxyCtx.global = true;

    let socksMatch;
    if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?(.+)/i))) {
        proxyCtx.enableType = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
        tempAccount = socksMatch[2].split('#')[0];
        proxyCtx.global = true;

        if (tempAccount.includes('@')) {
            const atIndex = tempAccount.lastIndexOf('@');
            let userPassword = tempAccount.substring(0, atIndex).replaceAll('%3D', '=');
            if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
                userPassword = atob(userPassword);
            }
            tempAccount = `${userPassword}@${tempAccount.substring(atIndex + 1)}`;
        }
    } else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=(.+)/i))) {
        const type = socksMatch[1].toLowerCase();
        tempAccount = socksMatch[2];
        proxyCtx.enableType = type.includes('http') ? 'http' : 'socks5';
        proxyCtx.global = type.startsWith('g') || proxyCtx.global;
    }

    if (tempAccount) {
        try {
            proxyCtx.parsedAddress = await 获取SOCKS5账号(tempAccount);
            if (searchParams.get('http')) proxyCtx.enableType = 'http';
        } catch (err) {
            proxyCtx.enableType = null;
        }
    }
    
    return proxyCtx;
}

async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    let hostname, port;
    if (hostPart.includes("]:")) {
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) {
        [hostname, port] = [hostPart, 80];
    } else {
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

function base64ToArrayBuffer(b64) {
    if (!b64) {
        return { error: null };
    }
    try {
        b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
        const dec = atob(b64);
        const buf = Uint8Array.from(dec, (c) => c.charCodeAt(0));
        return { earlyData: buf.buffer, error: null };
    } catch (e) {
        return { error: e };
    }
}

function sendWithRetry(sendFn) {
    for (let i = 0; i < 3; i++) {
        try {
            return sendFn();
        } catch (e) {
            if (i === 2) throw e;
            const jitter = 0.8 + Math.random() * 0.4;
            return new Promise(resolve => setTimeout(resolve, 1000 * (i + 1) * jitter)).then(() => sendWithRetry(sendFn));
        }
    }
}

function getPoemPage() {
    const mottoes = [
        {
            content: "天行健，君子以自强不息；地势坤，君子以厚德载物。",
            author: "《周易》",
            footer: "志当存高远，路自脚下行"
        },
        {
            content: "不积跬步，无以至千里；不积小流，无以成江海。",
           
 author: "荀子《劝学》",
            footer: "持之以恒，方能成就大业"
        },
        {
            content: "长风破浪会有时，直挂云帆济沧海。",
            author: "李白《行路难》",
            footer: "心怀希望，勇往直前"
        },
        {
            content: "宝剑锋从磨砺出，梅花香自苦寒来。",
 
            author: "《警世贤文》",
            footer: "磨难是成功的阶梯"
        },
        {
            content: "千淘万漉虽辛苦，吹尽狂沙始到金。",
            author: "刘禹锡《浪淘沙》",
            footer: "坚持到底，终见真金"
        },
        {
    
         content: "路漫漫其修远兮，吾将上下而求索。",
            author: "屈原《离骚》",
            footer: "永不止步的探索精神"
        },
        {
            content: "会当凌绝顶，一览众山小。",
            author: "杜甫《望岳》",
            footer: "志在巅峰，胸怀天下"
        },
  
       {
            content: "海纳百川，有容乃大；壁立千仞，无欲则刚。",
            author: "林则徐",
            footer: "胸怀宽广，意志坚定"
        },
        {
            content: "非淡泊无以明志，非宁静无以致远。",
            author: "诸葛亮《诫子书》",
            footer: 
"心静志远，淡泊明志"
        },
        {
            content: "精诚所至，金石为开。",
            author: "《后汉书》",
            footer: "真诚的力量无可阻挡"
        },
        {
            content: "志不强者智不达，言不信者行不果。",
            author: "墨子",
   
          footer: "意志坚定，言行一致"
        },
        {
            content: "老骥伏枥，志在千里；烈士暮年，壮心不已。",
            author: "曹操《龟虽寿》",
            footer: "永葆青春，志向不改"
        },
        {
            content: "天生我材必有用，千金散尽还复来。",
      
       author: "李白《将进酒》",
            footer: "自信自强，乐观向上"
        },
        {
            content: "穷且益坚，不坠青云之志。",
            author: "王勃《滕王阁序》",
            footer: "困境中更显志向坚定"
        },
        {
         
    content: "业精于勤，荒于嬉；行成于思，毁于随。",
            author: "韩愈《进学解》",
            footer: "勤奋思考，严谨行事"
        }
    ];
    const index = Math.floor(Math.random() * mottoes.length);
    const motto = mottoes[index];
    const mottoHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>励志座右铭</title>
    <style>
        body {
            font-family: "楷体", "Microsoft YaHei", sans-serif;
 background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: #333;
 }
        .motto-container {
            background: rgba(255, 255, 255, 0.95);
 padding: 40px 60px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 600px;
            backdrop-filter: blur(10px);
 }
        .motto-title {
            font-size: 2.5em;
 margin-bottom: 30px;
            color: #2d3748;
            font-weight: bold;
        }
        .motto-content {
            font-size: 1.4em;
 line-height: 2.2;
            color: #4a5568;
            margin-bottom: 30px;
            min-height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
 }
        .motto-author {
            font-size: 1.2em;
 color: #718096;
            font-style: italic;
            margin-bottom: 20px;
        }
        .motto-footer {
            margin-top: 30px;
 font-size: 0.9em;
            color: #a0aec0;
        }
        .time-info {
            margin-top: 25px;
 font-size: 0.9em;
            color: #a0aec0;
            font-family: monospace;
        }
        .refresh-hint {
            margin-top: 15px;
 font-size: 0.7em;
            color: #cbd5e0;
        }
        @keyframes fadeIn {
            from { opacity: 0;
 transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0);
 }
        }
        .motto-content, .motto-author, .motto-footer {
            animation: fadeIn 0.5s ease-out;
 }
    </style>
</head>
<body>
    <div class="motto-container">
        <h1 class="motto-title">励志座右铭</h1>
        <div class="motto-content">${motto.content}</div>
        <div class="motto-author">—— ${motto.author}</div>
        <div class="motto-footer">${motto.footer}</div>
        
        <div class="time-info" id="current-time">
            正在加载时间...
        </div>
        
        
 <div class="refresh-hint">
            刷新页面获取新的座右铭
        </div>
    </div>

    <script>
        function updateTime() {
            const now = new Date();
 const timeString = now.toLocaleString('zh-CN', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
           
      second: '2-digit',
                hour12: false
            });
 document.getElementById('current-time').textContent = timeString;
        }
        
        updateTime();
 setInterval(updateTime, 1000);
        
        window.addEventListener('load', function() {
            document.querySelector('.motto-container').style.animation = 'fadeIn 0.5s ease-out';
        });
 </script>
</body>
</html>`;
    
    return new Response(mottoHtml, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
            'Expires': '0',
            'Pragma': 'no-cache'
        }
    });
}

async function handleUsageAPI(req, env, ctx) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) {
        return ResponseBuilder.json({ success: false, error: 'Unauthorized' }, 401);
    }
    
    const config = await optimizeConfigLoading(env, ctx);
    const hasCloudflareConfig = config?.cfConfig && 
        config.cfConfig.accountId && 
        (config.cfConfig.apiToken || (config.cfConfig.email && config.cfConfig.globalApiKey));
    if (!hasCloudflareConfig) {
        return ResponseBuilder.json({ 
            success: false, 
            error: 'Cloudflare API not configured' 
        }, 400);
    }
    
    const usage = await getCloudflareUsage(env);
    return ResponseBuilder.json({ 
        success: usage.success, 
        usage: {
            pages: usage.pages,
            workers: usage.workers,
            total: usage.total
        }
    });
}

export default {
    async fetch(req, env, ctx) {
        try {
            await ldCfg(env, ctx);
            if (p === 'dylj' || p === '') {
                p = uid || 'dylj';
            }
            if (env.FDIP) {
                const servers = env.FDIP.split(',').map(s => s.trim());
                fdc = servers;
            }
            p = env.SUB_PATH || env.subpath || p;
            uid = env.UUID || env.uuid || env.AUTH || uid;
            dns = env.DNS_RESOLVER || dns;
            
            const upg = req.headers.get('Upgrade');
            const url = new URL(req.url);
            
            const config = await optimizeConfigLoading(env, ctx);
            const loginPath = config.klp || 'login';
            if (upg && upg.toLowerCase() === 'websocket') {
                const proxyCtx = await getRequestProxyConfig(req, config);
                return await VLOverWSHandler(req, config, proxyCtx);
            } else {
                const pathname = url.pathname;
                if (pathname === '/') {
                    const sessionId = getSessionCookie(req.headers.get('Cookie'));
                    const sessionResult = await validateAndRefreshSession(env, sessionId);
                    
                    if (sessionResult.valid) {
                        const host = req.headers.get('Host');
                        const base = `https://${host}`;
                        const response = await getMainPageContent(host, base, await gP(env), await gU(env), env);
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    } else {
                        const pw = await gP(env);
                        const u = await gU(env);
                        
                        if (!pw || !u) {
                            return getInitPage(req.headers.get('Host'), `https://${req.headers.get('Host')}`, true);
                        }
                        
                        return getPoemPage();
                    }
                }
                
                if (pathname === `/${loginPath}`) {
                    return await handleLogin(req, env);
                }
                
                switch (pathname) {
                    case `/${p}`:
                        return sub(req);
                    case '/info':
                        return await requireAuth(req, env, () => ResponseBuilder.json(req.cf));
                    case '/connect':
                        return await requireAuth(req, env, handleConnectTest);
                    case '/test-dns':
                        return await requireAuth(req, env, handleDNSTest);
                    case '/test-config':
                        return await requireAuth(req, env, handleConfigTest);
                    case '/test-failover':
                        return await requireAuth(req, env, handleFailoverTest);
                    case '/admin/save':
                        return await handleAdminSave(req, env);
                    case '/admin':
                        return await requireAuth(req, env, getAdminPage);
                    case '/init':
                        return await handleInit(req, env);
                    case '/zxyx':
                        return await requireAuth(req, env, zxyx);
                    case '/logout':
                        return await handleLogout(req, env);
                    case '/api/usage':
                        return await handleUsageAPI(req, env, ctx);
                    default:
                        return getPoemPage();
                }
            }
        } catch (err) {
            return ErrorHandler.internalError();
        }
    },
};

async function 整理成数组(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    const 地址数组 = 替换后的内容.split(',');
    return 地址数组;
}

async function getHomePage(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const pw = await gP(env);
    const u = await gU(env);
    
    if (!pw || !u) {
        return getInitPage(host, base, !pw && !u);
    }
    
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    const isAuthenticated = sessionResult.valid;
    
    if (isAuthenticated) {
        const response = await getMainPageContent(host, base, pw, u, env);
        if (sessionResult.refreshed) {
            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
        }
        return response;
    } else {
        return getPoemPage();
    }
}

function getLoginPage(url, baseUrl, showError = false, showPasswordChanged = false) {
    let messageHtml = '';
    if (showPasswordChanged) {
        messageHtml = `
        <div class="success-message">
            <i class="fas fa-check-circle"></i>
            <span>密码修改成功，请使用新密码重新登录。</span>
        </div>
        `;
    } else if (showError) {
        messageHtml = `
        <div class="error-message">
            <i class="fas fa-exclamation-circle"></i>
            <span>密码错误，请重试</span>
        </div>
        `;
    }

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 登录</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
            --success-bg: #c6f6d5;
            --success-border: #38a169;
            --success-text: #22543d;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
                --success-bg: #22543d;
                --success-border: #38a169;
                --success-text: #c6f6d5;
            }
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            overflow: hidden;
        }
        
        .login-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .error-message, .success-message {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            border: 1px solid var(--error-border);
        }
        
        .success-message {
            background: var(--success-bg);
            color: var(--success-text);
            border: 1px solid var(--success-border);
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔐</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">请输入密码以访问服务</p>
        
        ${messageHtml}
        
        <form method="post" action="/${cc?.klp || 'login'}">
            <div class="form-group">
                <label for="password" class="form-label">密码</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="请输入密码"
                    required
                    autofocus
                >
            </div>
            <button type="submit" class="btn-login">登录</button>
        </form>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

function getInitPage(url, baseUrl, isFirstTime = true) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 初始化设置</title>
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
            --generate-btn-bg: #ed8936;
            --generate-btn-hover: #dd6b20;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
                --generate-btn-bg: #ed8936;
                --generate-btn-hover: #dd6b20;
            }
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            overflow-y: auto;
        }
        
        .init-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 95%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 30px;
            font-size: 1rem;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-submit {
            width: 100%;
            padding: 12px 20px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        
        .btn-submit:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .btn-generate {
            width: 100%;
            padding: 8px 16px;
            background: var(--generate-btn-bg);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        
        .btn-generate:hover {
            background: var(--generate-btn-hover);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .footer {
            margin-top: 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-align: center;
        }
        
        .info-box {
            background: rgba(102, 126, 234, 0.1);
            padding: 12px 16px;
            margin-bottom: 20px;
            border-radius: 8px;
            text-align: left;
        }
        
        .info-box p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        @media (max-width: 480px) {
            .init-container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo {
                font-size: 2.5rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="init-container">
        <div class="logo">🚀</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">${isFirstTime ? '首次使用，请完成初始化设置' : '请完成系统设置'}</p>
        
        <div class="info-box">
            <p><strong>注意：</strong>请妥善保存设置的密码和UUID，它们将用于后续登录和客户端连接。</p>
        </div>
        
        <form action="/init" method="post">
            <div class="form-group">
                <label for="password" class="form-label">设置管理员密码</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="请设置管理员密码"
                    required
                    minlength="4"
                >
            </div>
            
            <div class="form-group">
                <label for="confirm_password" class="form-label">确认密码</label>
                <input 
                    type="password" 
                    id="confirm_password" 
                    name="confirm_password" 
                    class="form-input" 
                    placeholder="请再次输入密码"
                    required
                    minlength="4"
                >
            </div>
            
            <button type="button" class="btn-generate" onclick="generateUUID()">
                <i class="fas fa-sync-alt"></i>
                <span>生成随机UUID</span>
            </button>
            
            <div class="form-group">
                <label for="uuid" class="form-label">设置UUID</label>
                <input 
                    type="text" 
                    id="uuid" 
                    name="uuid" 
                    class="form-input" 
                    placeholder="请输入UUID或点击上方按钮生成"
                    required
                    pattern="[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                    title="请输入有效的UUID格式"
                >
            </div>
            
            <div class="form-group">
                <label for="login_path" class="form-label">自定义登录路径</label>
                <input 
                    type="text" 
                    id="login_path" 
                    name="login_path" 
                    class="form-input" 
                    placeholder="请输入自定义登录路径，如：login"
                    value="login"
                    required
                >
                <div class="form-help">设置后只能通过 域名/自定义路径 访问登录页面</div>
            </div>
            
            <button type="submit" class="btn-submit">完成设置</button>
        </form>
        
        <div class="footer">
            <p> © 2025 | 基于 Cloudflare Workers 的高性能网络服务</p>
        </div>
    </div>
    
    <script>
        function generateUUID() {
            const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            document.getElementById('uuid').value = uuid;
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            generateUUID();
            
            const passwordInput = document.getElementById('password');
            const confirmPasswordInput = document.getElementById('confirm_password');
            
            function validatePasswords() {
                if (passwordInput.value !== confirmPasswordInput.value) {
                    confirmPasswordInput.setCustomValidity('密码不匹配');
                } else {
                    confirmPasswordInput.setCustomValidity('');
                }
            }
            
            passwordInput.addEventListener('input', validatePasswords);
            confirmPasswordInput.addEventListener('input', validatePasswords);
            
            document.querySelector('form').addEventListener('submit', function(e) {
                if (passwordInput.value !== confirmPasswordInput.value) {
                    e.preventDefault();
                    alert('密码不匹配，请重新输入');
                    passwordInput.focus();
                }
            });
        });
    </script>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function handleInit(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    if (req.method !== 'POST') {
        return getInitPage(host, base, true);
    }
    
    const form = await req.formData();
    const password = form.get('password');
    const confirmPassword = form.get('confirm_password');
    const uuid = form.get('uuid');
    const loginPath = form.get('login_path') || 'login';
    if (password !== confirmPassword) {
        const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>错误</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #e53e3e; margin: 20px 0; }
        .btn { background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="error">错误：密码不匹配</div>
    <a href="/" class="btn">返回重新设置</a>
</body>
</html>`;
        return ResponseBuilder.html(html, 400);
    }
    
    if (!UUIDUtils.isValidUUID(uuid)) {
        const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>错误</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #e53e3e; margin: 20px 0; }
        .btn { background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="error">错误：UUID格式不正确</div>
    <a href="/" class="btn">返回重新设置</a>
</body>
</html>`;
        return ResponseBuilder.html(html, 400);
    }
    
    const savePassword = await sP(env, password);
    const saveUUID = await sU(env, uuid);
    const saveLoginPath = await saveConfigToKV(env, yx, fdc, uuid, null, null, null, loginPath);
    if (savePassword && saveUUID && saveLoginPath) {
        uid = uuid;
        const sessionId = generateSessionId();
        await saveSession(env, sessionId, 'admin');
        
        return ResponseBuilder.redirect(`${base}/${loginPath}`, 302, {
            'Set-Cookie': setSessionCookie(sessionId)
        });
    } else {
        const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>错误</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #e53e3e; margin: 20px 0; }
        .btn { background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="error">错误：保存配置失败</div>
    <a href="/" class="btn">返回重新设置</a>
</body>
</html>`;
        return ResponseBuilder.html(html, 500);
    }
}

async function getMainPageContent(host, base, pw, uuid, env) {
    const hasCloudflareConfig = cc?.cfConfig && 
        cc.cfConfig.accountId && 
        (cc.cfConfig.apiToken || (cc.cfConfig.email && cc.cfConfig.globalApiKey));
    const usageHtml = hasCloudflareConfig ? `
        <div class="info-group">
            <div class="info-label">
                <i class="fas fa-chart-bar"></i>
                请求用量统计
            </div>
            <div class="info-value" id="usage-stats">
                <span>加载中...</span>
            </div>
        </div>
    ` : '';
    
    const proxyCfg = cc?.proxyConfig || {};
    const proxyEnabled = proxyCfg.enabled;
    const proxyType = proxyCfg.type;
    const isGlobal = proxyCfg.global;
    
    const proxyStatusHtml = proxyEnabled ? `
        <div class="info-group">
            <div class="info-label">
                <i class="fas fa-plug"></i>
                代理状态
            </div>
            <div class="info-value">
                ${isGlobal ? '全局代理' : '名单代理'} | ${proxyType === 'http' ? 'HTTP' : 'SOCKS5'}
            </div>
        </div>
    ` : '';
    const protocolStatus = `
        <div class="info-group">
            <div class="info-label">
                <i class="fas fa-plug"></i>
                协议状态
            </div>
            <div class="info-value">
                VLESS: ${ev ? '✅ 启用' : '❌ 禁用'} | 
                Trojan: ${et ? '✅ 启用' : '❌ 禁用'}
            </div>
        </div>
    `;
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --bg-card: #f7fafc;
            --bg-button: #edf2f7;
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --text-button: #4a5568;
            --border-color: #e2e8f0;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-primary-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-secondary-bg: #edf2f7;
            --button-secondary-border: #cbd5e0;
            --status-bg: #f0fff4;
            --status-border: #c6f6d5;
            --status-text: #22543d;
            --status-dot: #48bb78;
            --toast-bg: #f0fff4;
            --toast-border: #48bb78;
            --toast-text: #2d3748;
            --toast-icon: #48bb78;
            --success-bg: #c6f6d5;
            --success-border: #38a169;
            --success-text: #22543d;
            --green-btn-bg: #10b981;
            --green-btn-hover: #059669;
            --purple-btn-bg: #667eea;
            --purple-btn-hover: #5a67d8;
            --red-btn-bg: #ef4444;
            --red-btn-hover: #dc2626;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --bg-card: #2d3748;
                --bg-button: #4a5568;
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --text-button: #e2e8f0;
                --border-color: #4a5568;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-primary-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-secondary-bg: #4a5568;
                --button-secondary-border: #718096;
                --status-bg: #22543d;
                --status-border: #2f855a;
                --status-text: #c6f6d5;
                --status-dot: #68d391;
                --toast-bg: #22543d;
                --toast-border: #38a169;
                --toast-text: #f0fff4;
                --toast-icon: #9ae6b4;
                --success-bg: #22543d;
                --success-border: #38a169;
                --success-text: #c6f6d5;
                --green-btn-bg: #059669;
                --green-btn-hover: #047857;
                --purple-btn-bg: #5a67d8;
                --purple-btn-hover: #4c51bf;
                --red-btn-bg: #dc2626;
                --red-btn-hover: #b91c1c;
            }
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }
        
        .container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 1000px;
            width: 100%;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
        }
        
        .admin-btn, .logout-btn {
            position: absolute;
            background: var(--bg-button);
            border: none;
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            z-index: 10;
            text-decoration: none;
            color: var(--text-button);
        }
        
        .admin-btn {
            top: 20px;
            left: 20px;
            color: var(--text-button);
        }
        
        .logout-btn {
            top: 20px;
            right: 20px;
            color: var(--text-button);
        }
        
        .logout-btn i, .admin-btn i {
            font-size: 0.9rem;
        }
        
        .logout-btn:hover, .admin-btn:hover {
            background: var(--bg-button);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .logo {
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .title {
            font-size: 1.8rem;
            margin-bottom: 8px;
            color: var(--text-title);
            text-align: center;
        }
        
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 15px;
            font-size: 1rem;
            text-align: center;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 25px;
            background: var(--status-bg);
            color: var(--status-text);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
            border: 1px solid var(--status-border);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--status-dot);
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        .success-message {
            background: var(--success-bg);
            color: var(--success-text);
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .cards-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 25px;
            width: 100%;
            align-items: center;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: 1px solid var(--border-color);
            width: 100%;
            max-width: 600px;
            text-align: left;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .card::-webkit-scrollbar {
            width: 6px;
        }
        
        .card::-webkit-scrollbar-track {
            background: var(--bg-button);
            border-radius: 3px;
        }
        
        .card::-webkit-scrollbar-thumb {
            background: var(--text-secondary);
            border-radius: 3px;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }
        
        .card-title {
            font-size: 1.2rem;
            margin-bottom: 15px;
            color: var(--text-title);
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
        }
        
        .card-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        
        .card-content.expanded {
            max-height: 500px;
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
        }
        
        .toggle-icon.expanded {
            transform: rotate(180deg);
        }
        
        .info-group {
            margin-bottom: 15px;
        }
        
        .info-label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 4px;
        }
        
        .info-value {
            color: var(--text-primary);
            font-size: 1rem;
            word-break: break-all;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .copy-btn {
            background: var(--button-secondary-bg);
            color: var(--text-button);
            border: 1px solid var(--button-secondary-border);
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        .copy-btn:hover {
            background: var(--input-bg);
            transform: translateY(-1px);
        }
        
        .buttons-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-bottom: 25px;
            width: 100%;
            max-width: 600px;
            align-items: center;
        }
        
        .btn-row {
            display: flex;
            justify-content: center;
            gap: 10px;
            width: 100%;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            min-width: 200px;
            flex: 1;
            max-width: 280px;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--button-primary-bg);
            color: white;
        }
        
        .btn-secondary {
            background: var(--button-secondary-bg);
            color: var(--text-button);
            border: 1px solid var(--button-secondary-border);
        }
        
        .btn-green {
            background: var(--green-btn-bg);
            color: white;
        }
        
        .btn-purple {
            background: var(--purple-btn-bg);
            color: white;
        }
        
        .btn-red {
            background: var(--red-btn-bg);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .btn-green:hover {
            background: var(--green-btn-hover);
        }
        
        .btn-purple:hover {
            background: var(--purple-btn-hover);
        }
        
        .btn-red:hover {
            background: var(--red-btn-hover);
        }
        
        .footer {
            margin-top: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--toast-bg);
            border-radius: 8px;
            padding: 12px 16px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 10px;
            z-index: 1000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
            max-width: 300px;
            color: var(--toast-text);
        }
        
        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }
        
        .toast-icon {
            width: 20px;
            height: 20px;
            background: var(--toast-icon);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        
        .toast-message {
            font-size: 14px;
            font-weight: 500;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 20px;
                margin: 10px;
            }
            
            .logout-btn, .admin-btn {
                top: 15px;
                padding: 8px 12px;
                font-size: 0.8rem;
            }
            
            .logout-btn {
                right: 15px;
            }
            
            .admin-btn {
                left: 15px;
            }
            
            .logo {
                font-size: 2rem;
            }
            
            .title {
                font-size: 1.5rem;
            }
            
            .card {
                padding: 15px;
                max-width: 100%;
            }
            
            .buttons-container {
                gap: 10px;
                margin-bottom: 15px;
            }
            
            .btn-row {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                min-width: 100%;
                max-width: 100%;
                padding: 10px 16px;
                font-size: 0.85rem;
            }
        }

        @media (max-width: 480px) {
            body {
                padding: 10px;
            }
            
            .container {
                padding: 15px;
            }
            
            .card {
                padding: 15px;
            }
            
            .toast {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: none;
                transform: translateY(-100%);
            }
            
            .toast.show {
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <button onclick="logout()" class="logout-btn">
            <i class="fas fa-sign-out-alt"></i>
            <span>退出</span>
        </button>
        
        <a href="/admin#advanced-config" class="admin-btn">
            <i class="fas fa-cog"></i>
            <span>配置</span>
        </a>
        
        <div class="logo">🚀</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">基于 Cloudflare Workers 的高性能网络服务</p>
        
        <div class="status-indicator">
            <span class="status-dot"></span>
            <span class="status-text">服务运行中</span>
        </div>
        
        <div class="cards-container">
            <div class="card">
                <div class="card-title" onclick="toggleCardContent('server-info')">
                    <span>
                        <i class="fas fa-server"></i>
                        服务器信息
                    </span>
                    <i class="fas fa-chevron-down toggle-icon" id="server-info-toggle"></i>
                </div>
                
                <div class="card-content" id="server-info-content">
                    <div class="info-group">
                        <div class="info-label">
                            <i class="fas fa-globe"></i>
                            主机地址
                        </div>
                        <div class="info-value">
                            ${host}
                        </div>
                    </div>
                    
                    ${protocolStatus}
                    
                    ${proxyStatusHtml}
                    
                    ${usageHtml}
                    
                    <div class="info-group">
                        <div class="info-label">
                            <i class="fas fa-key"></i>
                            UUID
                        </div>
                        <div class="info-value">
                            ${uuid}
                            <button class="copy-btn" onclick="copyToClipboard('${uuid}', 'UUID')">
                                <i class="fas fa-copy"></i>
                                复制
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title" onclick="toggleCardContent('subscription-info')">
                    <span>
                        <i class="fas fa-link"></i>
                        订阅信息
                    </span>
                    <i class="fas fa-chevron-down toggle-icon" id="subscription-info-toggle"></i>
                </div>
                
                <div class="card-content" id="subscription-info-content">
                    <div class="info-group">
                        <div class="info-label">
                            <i class="fas fa-code"></i>
                            Base64订阅
                        </div>
                        <div class="info-value">
                            ${base}/${uuid || 'dylj'}
                            <button class="copy-btn" onclick="copyToClipboard('${base}/${uuid || 'dylj'}', 'Base64订阅链接')">
                                <i class="fas fa-copy"></i>
                                复制
                            </button>
                        </div>
                    </div>
                    
                    <div class="info-group">
                        <div class="info-label">
                            <i class="fab fa-react"></i>
                            Clash订阅
                        </div>
                        <div class="info-value">
                            ${cpr}=${base}/${uuid || 'dylj'}
                            <button class="copy-btn" onclick="copyToClipboard('${cpr}=${base}/${uuid || 'dylj'}', 'Clash订阅链接')">
                                <i class="fas fa-copy"></i>
                                复制
                            </button>
                        </div>
                    </div>
                    
                    <div class="info-group">
                        <div class="info-label">
                            <i class="fas fa-box"></i>
                            Singbox订阅
                        </div>
                        <div class="info-value">
                            ${spr}=${base}/${uuid || 'dylj'}
                            <button class="copy-btn" onclick="copyToClipboard('${spr}=${base}/${uuid || 'dylj'}', 'Singbox订阅链接')">
                                <i class="fas fa-copy"></i>
                                复制
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="buttons-container">
            <div class="btn-row">
                <button onclick="copySubscription()" class="btn btn-secondary">
                    <i class="fas fa-code"></i>
                    <span>Base64订阅</span>
                </button>
                <button onclick="copyClashSubscription()" class="btn btn-secondary">
                    <i class="fab fa-react"></i>
                    <span>Clash订阅</span>
                </button>
            </div>
            <div class="btn-row">
                <button onclick="copySingboxSubscription()" class="btn btn-secondary">
                    <i class="fas fa-box"></i>
                    <span>Singbox订阅</span>
                </button>
                <a href="/admin#ip-management" class="btn btn-secondary">
                    <i class="fas fa-cog"></i>
                    <span>管理优选IP和反代IP</span>
                </a>
            </div>
            <div class="btn-row">
                <a href="/zxyx" class="btn btn-green">
                    <i class="fas fa-bolt"></i>
                    <span>在线优选工具</span>
                </a>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2025 | 基于 Cloudflare Workers 的高性能网络服务 & Powered By Leeshen</p>
        </div>
    </div>
    
    <script>
        function toggleCardContent(cardId) {
            const content = document.getElementById(cardId + '-content');
            const toggle = document.getElementById(cardId + '-toggle');
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                toggle.classList.remove('expanded');
            } else {
                content.classList.add('expanded');
                toggle.classList.add('expanded');
            }
        }
        
        function showToast(message) {
            const existingToast = document.querySelector('.toast');
            if (existingToast) {
                existingToast.remove();
            }
            
            const toast = document.createElement('div');
            toast.className = 'toast';
            
            const icon = document.createElement('div');
            icon.className = 'toast-icon';
            icon.textContent = '✓';
            
            const messageDiv = document.createElement('div');
            messageDiv.className = 'toast-message';
            messageDiv.textContent = message;
            
            toast.appendChild(icon);
            toast.appendChild(messageDiv);
            
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.classList.add('show');
            }, 10);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.parentNode.removeChild(toast);
                    }
                }, 300);
            }, 1500);
        }
        
        function copyToClipboard(text, description) {
            navigator.clipboard.writeText(text).then(() => {
                showToast(description + '已复制到剪贴板！');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showToast(description + '已复制到剪贴板！');
            });
        }
        
        function copySubscription() {
            const configUrl = '${base}/${uuid || 'dylj'}';
            copyToClipboard(configUrl, 'Base64订阅链接');
        }
        
        function copyClashSubscription() {
            const clashUrl = '${cpr}=${base}/${uuid || 'dylj'}';
            copyToClipboard(clashUrl, 'Clash订阅链接');
        }
        
        function copySingboxSubscription() {
            const singboxUrl = '${spr}=${base}/${uuid || 'dylj'}';
            copyToClipboard(singboxUrl, 'Singbox订阅链接');
        }
        
        function logout() {
            if (confirm('确定要退出登录吗？')) {
                window.location.href = '/logout';
            }
        }
        
        async function loadUsageStats() {
            try {
                const response = await fetch('/api/usage');
                const data = await response.json();
                
                if (data.success) {
                    const usage = data.usage;
                    const usagePercentage = (usage.total / 100000) * 100;
                    let usageColor = '#10b981';
                    let usageTextColor = '#10b981';
                    if (usagePercentage >= 80) {
                        usageColor = '#ef4444';
                        usageTextColor = '#ef4444';
                    } else if (usagePercentage >= 60) {
                        usageColor = '#ed8936';
                        usageTextColor = '#ed8936';
                    }
                    
                    const usageHTML = \`
                        <span style="color: \${usageTextColor}">Pages: \${usage.pages} | Workers: \${usage.workers} | 总计: \${usage.total}/100000</span>
                        <div style="margin-top: 5px; background: var(--input-bg); border-radius: 4px; overflow: hidden;">
                            <div style="width: \${Math.min(usagePercentage, 100)}%; background: \${usageColor}; height: 6px; transition: width 0.3s ease;"></div>
                        </div>
                        <div style="font-size: 0.8rem; color: \${usageTextColor}; margin-top: 2px;">
                            \${usagePercentage.toFixed(1)}% 使用率
                        </div>
                    \`;
                    
                    document.getElementById('usage-stats').innerHTML = usageHTML;
                } else {
                    document.getElementById('usage-stats').innerHTML = '<span>用量统计加载失败</span>';
                }
            } catch (error) {
                document.getElementById('usage-stats').innerHTML = '<span>用量统计加载失败</span>';
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            ${hasCloudflareConfig ? 'loadUsageStats();' : ''}
        });
    </script>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

function sub(req) {
    const host = req.headers.get('Host');
    const cfg = genConfig(uid, host);
    const content = btoa(cfg);
    return ResponseBuilder.text(content);
}

async function handleAdminSave(req, env) {
    try {
        const sessionId = getSessionCookie(req.headers.get('Cookie'));
        const sessionResult = await validateAndRefreshSession(env, sessionId);
        if (!sessionResult.valid) {
            return ErrorHandler.unauthorized();
        }
        
        const form = await req.formData();
        const cfipList = form.get('cfip') || '';
        const fdipList = form.get('fdip') || '';
        const u = form.get('uuid') || null;
        const clashP = form.get('clashPrefix') || '';
        const singP = form.get('singboxPrefix') || '';
        const currentPassword = form.get('current_password') || '';
        const newPassword = form.get('new_password') || '';
        const confirmPassword = form.get('confirm_password') || '';
        
        const protocolEv = form.get('protocol_ev') === 'on';
        const protocolEt = form.get('protocol_et') === 'on';
        const protocolTp = form.get('protocol_tp') || '';
        
        const cfApiMode = form.get('cf_api_mode') || 'token';
        const cfAccountId = form.get('cf_account_id') || '';
        const cfApiToken = form.get('cf_api_token') || '';
        const cfEmail = form.get('cf_email') || '';
        const cfGlobalApiKey = form.get('cf_global_api_key') || '';
        
        const proxyEnabled = form.get('proxy_enabled') === 'on';
        const proxyType = form.get('proxy_type') || 'socks5';
        const proxyAccount = form.get('proxy_account') || '';
        const proxyMode = form.get('proxy_mode') || 'whitelist';
        const proxyWhitelist = form.get('proxy_whitelist') || '';
        const loginPath = form.get('login_path') || 'login';
        
        if (u && !UUIDUtils.isValidUUID(u)) {
            return ResponseBuilder.text('UUID格式不正确', 400);
        }
        
        const cfipArr = cfipList.split('\n').map(x => x.trim()).filter(Boolean);
        const fdipArr = fdipList.split('\n').map(x => x.trim()).filter(Boolean);
        
        let passwordUpdated = false;
        let passwordError = '';
        if (currentPassword || newPassword || confirmPassword) {
            if (!currentPassword || !newPassword || !confirmPassword) {
                passwordError = '修改密码需要填写所有密码字段';
            } else if (currentPassword !== await gP(env)) {
                passwordError = '当前密码不正确';
            } else if (newPassword !== confirmPassword) {
                passwordError = '新密码和确认密码不匹配';
            } else {
                const savePassword = await sP(env, newPassword);
                if (!savePassword) {
                    passwordError = '密码更新失败';
                } else {
                    passwordUpdated = true;
                }
            }
        }
        
        if (passwordError) {
            const host = req.headers.get('Host');
            const base = `https://${host}`;
            return ResponseBuilder.redirect(`${base}/admin?message=${encodeURIComponent(passwordError)}`);
        }
        
        const protocolCfg = {
            ev: protocolEv,
            et: protocolEt, 
            tp: protocolTp
        };
        const cfCfg = {
            apiMode: cfApiMode,
            accountId: cfAccountId,
            apiToken: cfApiToken,
            email: cfEmail,
            globalApiKey: cfGlobalApiKey
        };
        const proxyCfg = {
            enabled: proxyEnabled,
            type: proxyType,
            account: proxyAccount,
            global: proxyMode === 'global',
            whitelist: proxyWhitelist.split('\n').map(x => x.trim()).filter(Boolean)
        };
        const ok1 = await saveConfigToKV(env, cfipArr, fdipArr, u, protocolCfg, cfCfg, proxyCfg, loginPath);
        const ok2 = await savePrefixConfigToKV(env, clashP, singP);
        if (ok1 && ok2) {
            yx = cfipArr;
            fdc = fdipArr;
            cpr = clashP;
            spr = singP;
            if (u) {
                uid = u;
            }
            
            ev = protocolEv;
            et = protocolEt;
            tp = protocolTp;
            protocolConfig = { ev, et, tp };
            
            const host = req.headers.get('Host');
            const base = `https://${host}`;
            if (passwordUpdated) {
                return ResponseBuilder.redirect(`${base}/${loginPath}?password_changed=true`);
            } else {
                return ResponseBuilder.redirect(`${base}/admin?message=${encodeURIComponent('配置已成功保存！')}`);
            }
        } else {
            const host = req.headers.get('Host');
            const base = `https://${host}`;
            return ResponseBuilder.redirect(`${base}/admin?message=${encodeURIComponent('保存配置失败')}`);
        }
    } catch (e) {
        const host = req.headers.get('Host');
        const base = `https://${host}`;
        return ResponseBuilder.redirect(`${base}/admin?message=${encodeURIComponent('保存配置时发生错误')}`);
    }
}

async function getAdminPage(req, env) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) {
        return ErrorHandler.unauthorized();
    }
    
    const url = new URL(req.url);
    const message = url.searchParams.get('message');
    if (!cc || !yx.length || !fdc.length) {
        await ldCfg(env); 
    }
    
    const cfConfig = cc?.cfConfig || {};
    const proxyConfig = cc?.proxyConfig || {};
    const loginPathSection = `
        <div class="form-group">
            <label for="login_path" class="form-label">登录路径</label>
            <input 
                type="text" 
                id="login_path" 
                name="login_path" 
                class="form-input" 
                value="${cc?.klp || 'login'}"
                placeholder="请输入自定义登录路径"
                required
            />
            <div class="form-help">设置后只能通过 域名/自定义路径 访问登录页面</div>
        </div>
    `;
    const proxyConfigSection = `
    <div class="form-group">
        <label class="form-label">SOCKS5/HTTP 代理配置</label>
        <div style="padding: 15px; background: rgba(102, 126, 234, 0.05); border-radius: 8px; border: 1px solid var(--input-border);">
            <div style="margin-bottom: 12px;">
                <label style="display: flex; align-items: center; cursor: pointer;">
                    <input type="checkbox" id="proxy_enabled" name="proxy_enabled" ${proxyConfig.enabled 
? 'checked' : ''} style="margin-right: 8px;">
                    <span>启用 SOCKS5/HTTP 代理转发</span>
                </label>
            </div>
            
            <div class="form-group">
                <label for="proxy_type" class="form-label">代理类型</label>
                <select id="proxy_type" name="proxy_type" class="form-input">
                    <option value="socks5" ${proxyConfig.type === 'socks5' ?
'selected' : ''}>SOCKS5</option>
                    <option value="http" ${proxyConfig.type === 'http' ?
'selected' : ''}>HTTP</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="proxy_account" class="form-label">代理服务器地址</label>
                <input 
                    type="text" 
                    id="proxy_account" 
                    name="proxy_account" 
                    class="form-input" 
                    value="${proxyConfig.account || ''}"
                    placeholder="格式: [协议://][用户名:密码@]主机:端口"
                />
                <div class="form-help">
                    支持格式：
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        <li>host:port (无认证)</li>
                        <li>user:pass@host:port (基础认证)</li>
                        <li>socks5://user:pass@host:port (明确协议)</li>
                        <li>http://user:pass@proxy.com:8080 (HTTP代理)</li>
                        <li>[2001:db8::1]:1080 (IPv6地址)</li>
                    </ul>
                    认证信息支持Base64编码
                </div>
            </div>
            
            <div class="form-group">
                <label class="form-label">代理模式</label>
                <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="radio" name="proxy_mode" value="whitelist" ${!proxyConfig.global ? 'checked' : ''} style="margin-right: 8px;">
                        <span>名单代理</span>
                    </label>
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="radio" name="proxy_mode" value="global" ${proxyConfig.global ? 'checked' : ''} style="margin-right: 8px;">
                        <span>全局代理</span>
                    </label>
                </div>
                <div class="form-help">
                    • <strong>名单代理</strong>: 仅对白名单内的域名使用代理（推荐）<br>
                    • <strong>全局代理</strong>: 所有连接都通过代理（性能较低）
                </div>
            </div>
            
            <div class="form-group">
                <label for="proxy_whitelist" class="form-label">代理白名单（每行一个域名）</label>
                <textarea 
                    id="proxy_whitelist" 
                    name="proxy_whitelist" 
                    class="form-textarea" 
                    placeholder="请输入需要代理的域名，每行一个&#10;支持通配符，例如：*.example.com&#10;默认包含常见CDN域名"
                    style="min-height: 100px;"
                >${(proxyConfig.whitelist || []).join('\n')}</textarea>
                <div class="form-help">
                    名单代理模式下，只有匹配这些模式的域名才会通过代理连接<br>
                    支持通配符：<code>*</code> 匹配任意字符，<code>?</code> 匹配单个字符
                </div>
            </div>
            
            <div class="form-help">
                <strong>使用场景：</strong><br>
                • 访问被墙的CDN资源时使用代理<br>
                • 优化特定域名的网络路径<br>
                • 通过代理访问地理位置限制的内容
            </div>
        </div>
    </div>
`;
    const cfConfigSection = `
        <div class="form-group">
            <label class="form-label">Cloudflare API 配置</label>
            <div style="padding: 15px; background: rgba(102, 126, 234, 0.05); border-radius: 8px; border: 1px solid var(--input-border);">
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <input type="radio" id="cf_api_mode_token" name="cf_api_mode" value="token" ${cfConfig.apiMode !== 'email' ?
'checked' : ''} onchange="toggleCFMode()">
                        <span>Account ID + API Token</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="radio" id="cf_api_mode_email" name="cf_api_mode" value="email" ${cfConfig.apiMode === 'email' ?
'checked' : ''} onchange="toggleCFMode()">
                        <span>邮箱 + Global API Key</span>
                    </label>
                </div>
                
                <div id="cf_token_section" style="${cfConfig.apiMode === 'email' ? 'display: none;' : ''}">
                    <div class="form-group">
                        <label for="cf_account_id" class="form-label">Account ID</label>
                        <input 
                            type="text" 
                            id="cf_account_id" 
                            name="cf_account_id" 
                            class="form-input" 
                            value="${cfConfig.accountId || ''}"
                            placeholder="请输入 Cloudflare Account ID"
                        />
                    </div>
                    
                    <div class="form-group">
                        <label for="cf_api_token" class="form-label">API Token</label>
                        <input 
                            type="password" 
                            id="cf_api_token" 
                            name="cf_api_token" 
                            class="form-input" 
                            value="${cfConfig.apiToken || ''}"
                            placeholder="请输入 Cloudflare API Token"
                        />
                        <div class="form-help">API 令牌权限使用"阅读分析数据和日志"模板即可</div>
                    </div>
                </div>
                
                <div id="cf_email_section" style="${cfConfig.apiMode === 'email' ?
'' : 'display: none;'}">
                    <div class="form-group">
                        <label for="cf_email" class="form-label">邮箱</label>
                        <input 
                            type="email" 
                            id="cf_email" 
                            name="cf_email" 
                            class="form-input" 
                            value="${cfConfig.email ||
''}"
                            placeholder="请输入 Cloudflare 邮箱"
                        />
                    </div>
                    
                    <div class="form-group">
                        <label for="cf_global_api_key" class="form-label">Global API Key</label>
                        <input 
                            type="password" 
                            id="cf_global_api_key" 
                            name="cf_global_api_key" 
                            class="form-input" 
                            value="${cfConfig.globalApiKey ||
''}"
                            placeholder="请输入 Cloudflare Global API Key"
                        />
                    </div>
                </div>
                
                <div class="form-help">
                    配置后可在主页查看 Workers/Pages 请求用量统计
                </div>
            </div>
        </div>
    `;
    
    const protocolConfigSection = `
        <div class="form-group">
            <label class="form-label">协议配置</label>
            <div style="padding: 15px; background: rgba(102, 126, 234, 0.05); border-radius: 8px; border: 1px solid var(--input-border);">
                <div style="margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="protocol_ev" name="protocol_ev" ${ev ? 'checked' : ''} style="margin-right: 8px;">
                        <span>启用 VLESS 协议</span>
                    </label>
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; cursor: pointer;">
                        <input type="checkbox" id="protocol_et" name="protocol_et" ${et ? 'checked' : ''} style="margin-right: 8px;">
                        <span>启用 Trojan 协议</span>
                    </label>
                </div>
                <div style="margin-top: 15px;">
                    <label for="protocol_tp" class="form-label">Trojan 密码 (可选)</label>
                    <input 
                        type="text" 
                        id="protocol_tp" 
                        name="protocol_tp" 
                        class="form-input" 
                        value="${tp}"
                        placeholder="留空则自动使用 UUID"
                    >
                    <div class="form-help">设置自定义 Trojan 密码。留空则使用 UUID。</div>
                </div>
                <div class="form-help" style="margin-top: 10px;">
                    可以同时启用多个协议。订阅将生成选中协议的节点。<br>
                    • VLESS: 基于 WebSocket 的标准协议<br>
                    • Trojan: 使用 SHA224 密码认证
                </div>
            </div>
        </div>
    `;
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 配置管理</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --bg-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-container: rgba(255, 255, 255, 0.95);
            --bg-card: #f7fafc;
            --text-primary: #333;
            --text-secondary: #718096;
            --text-title: #2d3748;
            --border-color: #e2e8f0;
            --input-bg: #fff;
            --input-border: #e2e8f0;
            --input-focus: #667eea;
            --button-bg: linear-gradient(45deg, #667eea, #764ba2);
            --button-hover: linear-gradient(45deg, #5a67d8, #6b46c1);
            --success-bg: #c6f6d5;
            --success-border: #38a169;
            --success-text: #22543d;
            --error-bg: #fed7d7;
            --error-border: #e53e3e;
            --error-text: #c53030;
            --generate-btn-bg: #ed8936;
            --generate-btn-hover: #dd6b20;
            --section-bg: #f8fafc;
            --section-border: #e2e8f0;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
                --bg-container: rgba(26, 32, 44, 0.95);
                --bg-card: #2d3748;
                --text-primary: #e2e8f0;
                --text-secondary: #a0aec0;
                --text-title: #f7fafc;
                --border-color: #4a5568;
                --input-bg: #2d3748;
                --input-border: #4a5568;
                --input-focus: #63b3ed;
                --button-bg: linear-gradient(45deg, #4a5568, #2d3748);
                --button-hover: linear-gradient(45deg, #718096, #4a5568);
                --success-bg: #22543d;
                --success-border: #38a169;
                --success-text: #c6f6d5;
                --error-bg: #742a2a;
                --error-border: #e53e3e;
                --error-text: #fc8181;
                --generate-btn-bg: #ed8936;
                --generate-btn-hover: #dd6b20;
                --section-bg: #2d3748;
                --section-border: #4a5568;
            }
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            padding: 20px;
            color: var(--text-primary);
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        
        .admin-container {
            background: var(--bg-container);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 1000px;
            width: 100%;
            max-height: none;
            min-height: 500px;
            height: auto;
            overflow-y: auto;
        }
        
        .admin-container::-webkit-scrollbar {
            width: 8px;
        }
        
        .admin-container::-webkit-scrollbar-track {
            background: var(--bg-button);
            border-radius: 4px;
        }
        
        .admin-container::-webkit-scrollbar-thumb {
            background: var(--text-secondary);
            border-radius: 4px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .title {
            font-size: 2rem;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .back-btn {
            background: var(--bg-card);
            color: var(--text-secondary);
            border: none;
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            text-decoration: none;
        }
        
        .back-btn:hover {
            background: var(--bg-card);
            transform: translateY(-1px);
        }
        
        .config-section {
            margin-bottom: 25px;
            background: var(--section-bg);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--section-border);
        }
        
        .section-header {
            padding: 16px 20px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--section-border);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.3s ease;
        }
        
        .section-header:hover {
            background: rgba(102, 126, 234, 0.05);
        }
        
        .section-title {
            font-size: 1.3rem;
            color: var(--text-title);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
        }
        
        .toggle-icon.expanded {
            transform: rotate(180deg);
        }
        
        .section-content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .section-content.expanded {
            padding: 20px;
            max-height: none;
            overflow-y: visible;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .form-input {
            width: 100%;
            padding: 10px 14px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        
        .form-textarea {
            width: 100%;
            min-height: 150px;
            padding: 10px 14px;
            border: 2px solid var(--input-border);
            border-radius: 8px;
            font-size: 1rem;
            font-family: monospace;
            transition: border-color 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
            resize: vertical;
        }
        
        .form-textarea:focus {
            outline: none;
            border-color: var(--input-focus);
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-save {
            padding: 12px 24px;
            background: var(--button-bg);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-save:hover {
            background: var(--button-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
        
        .btn-generate {
            padding: 8px 16px;
            background: var(--generate-btn-bg);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            margin-left: 10px;
            transition: all 0.3s ease;
        }
        
        .btn-generate:hover {
            background: var(--generate-btn-hover);
        }
        
        .success-message, .error-message {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .success-message {
            background: var(--success-bg);
            color: var(--success-text);
            border: 1px solid var(--success-border);
        }
        
        .error-message {
            background: var(--error-bg);
            color: var(--error-text);
            border: 1px solid var(--error-border);
        }
        
        @media (max-width: 768px) {
            .admin-container {
                padding: 20px;
            }
            
            .title {
                font-size: 1.5rem;
            }
            
            .section-title {
                font-size: 1.2rem;
            }
            
            .header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .back-btn {
                align-self: flex-start;
            }
            
            .section-content.expanded {
                padding: 15px;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 10px;
            }
            
            .admin-container {
                padding: 15px;
            }
            
            .title {
                font-size: 1.3rem;
            }
            
            .section-title {
                font-size: 1.1rem;
            }
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="header">
            <h1 class="title"><i class="fas fa-cog"></i> Workers Service 配置管理</h1>
            <a href="/" class="back-btn">
                <i class="fas fa-arrow-left"></i>
                返回主页
            </a>
        </div>
        
        ${message ?
`
        <div class="${message.includes('成功') ? 'success-message' : 'error-message'}" id="success-message">
            <i class="fas ${message.includes('成功') ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
            <span>${message}</span>
        </div>
        <script>
            setTimeout(() => {
                const message = document.getElementById('success-message');
                if (message) {
                    message.style.display = 'none';
                }
            }, 3000);
        </script>
        ` : ''}
        
        <form action="/admin/save" method="post">
            <div class="config-section" id="ip-management">
                <div class="section-header" onclick="toggleSection('ip-management')">
                    <h2 class="section-title"><i class="fas fa-server"></i> IP配置</h2>
                    <i class="fas fa-chevron-down toggle-icon" id="ip-management-toggle"></i>
                </div>
                
                <div class="section-content" id="ip-management-content">
                    <div class="form-group">
                        <label for="cfip" class="form-label">优选IP/域名列表（每行一个）</label>
                        <textarea 
                            id="cfip" 
                            name="cfip" 
                            class="form-textarea" 
                            placeholder="请输入优选IP或域名，每行一个&#10;支持格式：&#10;172.64.144.13:8443#日本|JP或&#10;example.com:8443#日本|JP"
                        >${yx.join('\n')}</textarea>
                        <div class="form-help">这些IP/域名将用于Web界面伪装和订阅生成。支持自定义端口和国家信息，格式：IP:端口#国家名称|国家代码</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="fdip" class="form-label">反代IP/域名列表（每行一个）</label>
                        <textarea 
                            id="fdip" 
                            name="fdip" 
                            class="form-textarea" 
                            placeholder="请输入反代IP或域名，每行一个&#10;例如：&#10;13.230.34.30:8443#日本&#10;或example.com:8443#日本"
                        >${fdc.join('\n')}</textarea>
                        <div class="form-help">这些IP/域名将用于实际代理连接，格式：IP、域名、IP:端口、域名:端口、支持#注释
                      </div>
                    </div>
                </div>
            </div>
            
            <div class="config-section" id="advanced-config">
                <div class="section-header" onclick="toggleSection('advanced-config')">
                    <h2 class="section-title"><i class="fas fa-cogs"></i> 高级配置</h2>
                    <i class="fas fa-chevron-down toggle-icon" id="advanced-config-toggle"></i>
                </div>
                
                <div class="section-content" id="advanced-config-content">
                    
                    ${protocolConfigSection}
                    
                    ${proxyConfigSection}
                    
                    ${cfConfigSection}

                    ${loginPathSection}
                    
                    <div class="form-group">
                        <label for="uuid" class="form-label">UUID</label>
                        <div style="display: flex; align-items: center;">
                            <input 
                                type="text" 
                                id="uuid" 
                                name="uuid" 
                                class="form-input" 
                                value="${uid}"
                                placeholder="请输入UUID"
                                pattern="[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                                title="请输入有效的UUID格式"
                                style="flex: 1;"
                            >
                            <button type="button" class="btn-generate" onclick="generateUUID()">
                                <i class="fas fa-sync-alt"></i>
                                <span>随机生成</span>
                            </button>
                        </div>
                        <div class="form-help">用于客户端连接的唯一标识符，必须符合UUID格式</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="clashPrefix" class="form-label">Clash订阅前缀</label>
                        <input 
                            type="text" 
                            id="clashPrefix" 
                            name="clashPrefix" 
                            class="form-input" 
                            value="${cpr}"
                            placeholder="https://sublink.eooce.com/clash?config"
                        />
                        <div class="form-help">用于生成Clash订阅链接的前缀地址</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="singboxPrefix" class="form-label">Singbox订阅前缀</label>
                        <input 
                            type="text" 
                            id="singboxPrefix" 
                            name="singboxPrefix" 
                            class="form-input" 
                            value="${spr}"
                            placeholder="https://sublink.eooce.com/singbox?config"
                        />
                        <div class="form-help">用于生成Singbox订阅链接的前缀地址</div>
                    </div>
                    
                    <div class="fragment-config">
                        <h3 class="section-title"><i class="fas fa-key"></i> 修改管理员密码</h3>
                        <div class="form-group">
                            <label for="current_password" class="form-label">当前密码</label>
                            <input 
                                type="password" 
                                id="current_password" 
                                name="current_password" 
                                class="form-input" 
                                placeholder="请输入当前密码"
                            >
                        </div>
                        
                        <div class="form-group">
                            <label for="new_password" class="form-label">新密码</label>
                            <input 
                                type="password" 
                                id="new_password" 
                                name="new_password" 
                                class="form-input" 
                                placeholder="请输入新密码"
                            >
                        </div>
                        
                        <div class="form-group">
                            <label for="confirm_password" class="form-label">确认新密码</label>
                            <input 
                                type="password" 
                                id="confirm_password" 
                                name="confirm_password" 
                                class="form-input" 
                                placeholder="请再次输入新密码"
                            >
                        </div>
                        <div class="form-help">如需修改密码，请填写以上三个字段；如不需要修改，请留空</div>
                    </div>
                </div>
            </div>
            
            <button type="submit" class="btn-save">
                <i class="fas fa-save"></i>
                <span>保存配置</span>
            </button>
        </form>
    </div>
    
    <script>
        function generateUUID() {
            const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
            document.getElementById('uuid').value = uuid;
        }
        
        function toggleCFMode() {
            const tokenMode = document.getElementById('cf_api_mode_token').checked;
            document.getElementById('cf_token_section').style.display = tokenMode ? 'block' : 'none';
            document.getElementById('cf_email_section').style.display = tokenMode ? 'none' : 'block';
        }
        
        function toggleSection(sectionId) {
            const content = document.getElementById(sectionId + '-content');
            const toggle = document.getElementById(sectionId + '-toggle');
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                toggle.classList.remove('expanded');
            } else {
                content.classList.add('expanded');
                toggle.classList.add('expanded');
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const urlHash = window.location.hash;
            
            if (urlHash === '#advanced-config') {
                document.getElementById('ip-management-content').classList.remove('expanded');
                document.getElementById('ip-management-toggle').classList.remove('expanded');
                
                document.getElementById('advanced-config-content').classList.add('expanded');
                document.getElementById('advanced-config-toggle').classList.add('expanded');
            } else {
                document.getElementById('ip-management-content').classList.add('expanded');
                document.getElementById('ip-management-toggle').classList.add('expanded');
                
                document.getElementById('advanced-config-content').classList.remove('expanded');
                document.getElementById('advanced-config-toggle').classList.remove('expanded');
            }
        });
    </script>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function handleConnectTest(req, env) {
    try {
        const { socket, server } = await universalConnectWithFailover();
        socket.close();
        return ResponseBuilder.json({
            success: true,
            message: `成功连接到 ${server.original}`,
            server: server
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `连接失败: ${e.message}`
        }, 500);
    }
}

async function handleDNSTest(req, env) {
    try {
        const res = await fetch(dns, {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1])
        });
        const ans = await res.arrayBuffer();
        return ResponseBuilder.json({
            success: true,
            message: 'DNS查询成功',
            response: new Uint8Array(ans).slice(0, 100)
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `DNS查询失败: ${e.message}`
        }, 500);
    }
}

async function handleConfigTest(req, env) {
    try {
        const host = req.headers.get('Host');
        const config = genConfig(uid, host);
        return ResponseBuilder.json({
            success: true,
            message: '配置生成成功',
            config: config
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `配置生成失败: ${e.message}`
        }, 500);
    }
}

async function handleFailoverTest(req, env) {
    try {
        const testResults = [];
        const servers = [...fdc, 'Kr.tp50000.netlib.re'];
        
        for (let i = 0; i < servers.length; i++) {
            const s = servers[i];
            try {
                const { hostname, port } = IPParser.parseConnectionAddress(s);
                const rh = await optimizedResolveHostname(hostname);
                const socket = await connect({
                    hostname: rh,
                    port: port,
                    connectTimeout: globalTimeout
                });
                socket.close();
                testResults.push({
                    server: s,
                    status: 'success',
                    message: `连接成功`
                });
            } catch (e) {
                testResults.push({
                    server: s,
                    status: 'failed',
                    message: `连接失败: ${e.message}`
                });
            }
        }
        
        return ResponseBuilder.json({
            success: true,
            message: '故障转移测试完成',
            results: testResults
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `故障转移测试失败: ${e.message}`
        }, 500);
    }
}

async function zxyx(request, env, txt = 'ADD.txt') {
    const sessionId = getSessionCookie(request.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    
    if (!sessionResult.valid) {
        const html = `<!DOCTYPE html>
<html>
<head>
    <title>未授权访问</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: #e53e3e; margin: 20px 0; font-size: 1.2em; }
        .btn { background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px; }
        .info { color: #666; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="error">未授权访问，请先登录</div>
    <div class="info">请登录后访问在线优选工具</div>
    <a href="/${cc?.klp || 'login'}" class="btn">返回登录页面</a>
    <script>
        setTimeout(() => {
            window.location.href = '/${cc?.klp || 'login'}';
        }, 3000);
    </script>
</body>
</html>`;
        return new Response(html, {
            status: 200,
            headers: { 
                'Content-Type': 'text/html;charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            }
        });
    }

    const countryCodeToName = {
        'US': '美国', 'SG': '新加坡', 'DE': '德国', 'JP': '日本', 'KR': '韩国',
        'HK': '香港', 'TW': '台湾', 'GB': '英国', 'FR': '法国', 'IN': '印度',
        'BR': '巴西', 'CA': '加拿大', 'AU': '澳大利亚', 'NL': '荷兰', 'CH': '瑞士',
        'SE': '瑞典', 'IT': '意大利', 'ES': '西班牙', 'RU': '俄罗斯', 'ZA': '南非',
        'MX': '墨西哥', 'MY': '马来西亚', 'TH': '泰国', 'ID': '印度尼西亚', 'VN': '越南',
        'PH': '菲律宾', 'TR': '土耳其', 'SA': '沙特阿拉伯', 'AE': '阿联酋', 'EG': '埃及',
        'NG': '尼日利亚', 'IL': '以色列', 'PL': '波兰', 'UA': '乌克兰', 'CZ': '捷克',
        'RO': '罗马尼亚', 'GR': '希腊', 'PT': '葡萄牙', 'DK': '丹麦', 'FI': '芬兰',
        'NO': '挪威', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰', 'LU': '卢森堡',
        'CY': '塞浦路斯', 'MT': '马耳他', 'IS': '冰岛', 'CN': '中国'
    };

    function getCountryName(countryCode) {
        return countryCodeToName[countryCode] || countryCode;
    }

    if (!env.SJ) {
        env.SJ = env.SJ || env.sj;
    }
    
    const country = request.cf?.country || 'CN';
    
    async function getNipDomain() {
        try {
            const response = await fetch(atob('aHR0cHM6Ly9jbG91ZGZsYXJlLWRucy5jb20vZG5zLXF1ZXJ5P25hbWU9bmlwLjA5MDIyNy54eXomdHlwZT1UWFQ='), {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
                    const txtRecord = data.Answer[0].data;
                    const domain = txtRecord.replace(/^"(.*)"$/, '$1');
                    return domain;
                }
            }
            return atob('bmlwLmxmcmVlLm9yZw==');
        } catch (error) {
            return atob('aXAuMDkwMjI3Lnh5eg==');
        }
    }
    
    const nipDomain = await getNipDomain();
    
    const LATENCY_CALIBRATION_FACTOR = 0.25;
    
    function calibrateLatency(rawLatency) {
        return Math.max(1, Math.round(rawLatency * LATENCY_CALIBRATION_FACTOR));
    }
    
    function isRetriableError(error) {
        if (!error) return false;
        
        const errorMessage = error.message || error.toString();
        const retryablePatterns = [
            'timeout', 'abort', 'network', 'fetch', 'failed',
            'load failed', 'connection', 'socket', 'reset'
        ];
        
        const nonRetryablePatterns = [
            'HTTP 4', 'HTTP 5', '404', '500', '502', '503',
            'certificate', 'SSL', 'TLS', 'CORS', 'blocked'
        ];
        
        const isRetryable = retryablePatterns.some(pattern => 
            errorMessage.toLowerCase().includes(pattern.toLowerCase())
        );
        
        const isNonRetryable = nonRetryablePatterns.some(pattern => 
            errorMessage.toLowerCase().includes(pattern.toLowerCase())
        );
        
        return isRetryable && !isNonRetryable;
    }
    
    async function smartRetry(operation, maxAttempts = 3, baseDelay = 200, timeout = 5000) {
        let lastError;
        
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            
            try {
                const result = await Promise.race([
                    operation(controller.signal),
                    new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('Operation timeout')), timeout)
                    )
                ]);
                
                clearTimeout(timeoutId);
                
                if (result && result.success !== false) {
                    return result;
                }
                
                if (result && result.error) {
                    if (result.error.includes('HTTP 4') || result.error.includes('HTTP 5')) {
                        return result;
                    }
                }
                
                lastError = result ? result.error : new Error('Operation failed');
                
            } catch (error) {
                clearTimeout(timeoutId);
                lastError = error;
                
                if (!error.message.includes('network') && 
                    !error.message.includes('timeout') && 
                    !error.message.includes('fetch')) {
                    throw error;
                }
            }
            
            if (attempt < maxAttempts) {
                const delay = baseDelay * Math.pow(2, attempt - 1) + Math.random() * 100;
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        
        throw lastError;
    }
    
    async function adaptiveSpeedTest(ip, port, calibratedLatency, customTestUrl) {
        if (calibratedLatency >= 1500) {
            return {
                success: false,
                error: '延迟过高，跳过测速',
                speed: null
            };
        }
        
        const testProfiles = {
            'excellent': { 
                size: 2 * 1024 * 1024,
                timeout: 8000,
                quickSize: 256 * 1024,
                quickTimeout: 4000
            },
            'good': { 
                size: 1 * 1024 * 1024,
                timeout: 10000,
                quickSize: 128 * 1024,
                quickTimeout: 4000
            },
            'fair': { 
                size: 512 * 1024,
                timeout: 12000,
                quickSize: 64 * 1024,
                quickTimeout: 5000
            },
            'poor': { 
                size: 256 * 1024,
                timeout: 15000,
                quickSize: 32 * 1024,
                quickTimeout: 6000
            }
        };
        
        let profile;
        if (calibratedLatency < 80) {
            profile = testProfiles.excellent;
        } else if (calibratedLatency < 300) {
            profile = testProfiles.good;
        } else if (calibratedLatency < 600) {
            profile = testProfiles.fair;
        } else {
            profile = testProfiles.poor;
        }
        
        const fallbackUrls = [
            'https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin',
            'https://speed.cloudflare.com/__down?bytes=8388608',
            'https://cachefly.cachefly.net/100mb.test',
            'https://proof.ovh.net/files/100Mb.dat'
        ];
        
        let testUrl = customTestUrl;
        if (!testUrl) {
            testUrl = fallbackUrls[0];
        }
        
        const quickResult = await smartRetry(
            async (signal) => {
                let result = await testDownloadSpeedWithSize(ip, port, profile.quickSize, profile.quickTimeout, testUrl, signal);
                
                if (!result.success && !customTestUrl) {
                    for (let i = 1; i < fallbackUrls.length && !result.success; i++) {
                        try {
                            result = await testDownloadSpeedWithSize(ip, port, profile.quickSize, profile.quickTimeout, fallbackUrls[i], signal);
                        } catch (e) {
                            continue;
                        }
                    }
                }
                return result;
            },
            2,
            200,
            profile.quickTimeout + 1000
        );
        
        if (!quickResult.success || quickResult.speed < 0.3) {
            return {
                success: false,
                error: '快速测速不达标',
                speed: null
            };
        }
        
        await new Promise(resolve => setTimeout(resolve, 200));
        
        const fullResult = await smartRetry(
            async (signal) => {
                let result = await testDownloadSpeedWithSize(ip, port, profile.size, profile.timeout, testUrl, signal);
                
                if (!result.success && !customTestUrl) {
                    for (let i = 1; i < fallbackUrls.length && !result.success; i++) {
                        try {
                            result = await testDownloadSpeedWithSize(ip, port, profile.size, profile.timeout, fallbackUrls[i], signal);
                        } catch (e) {
                            continue;
                        }
                    }
                }
                return result;
            },
            2,
            300,
            profile.timeout + 1000
        );
        
        return validateSpeedResult(fullResult);
    }
    
    async function testDownloadSpeedWithSize(ip, port, targetBytes, timeout, customTestUrl, abortSignal) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        if (abortSignal) {
            abortSignal.addEventListener('abort', () => controller.abort());
        }
        
        try {
            const startTime = Date.now();
            let downloadedBytes = 0;
            
            const testUrl = customTestUrl || `https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin`;
            
            const requestOptions = {
                signal: controller.signal
            };
            
            if (typeof globalThis !== 'undefined' && globalThis.process && globalThis.process.env) {
            } else {
                requestOptions.cf = {
                    resolveOverride: ip
                };
            }
            
            const response = await fetch(testUrl, requestOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const reader = response.body.getReader();
            const chunks = [];
            
            while (downloadedBytes < targetBytes) {
                const { done, value } = await reader.read();
                
                if (done) {
                    break;
                }
                
                chunks.push(value);
                downloadedBytes += value.length;
                
                if (downloadedBytes >= targetBytes) {
                    break;
                }
                
                if (controller.signal.aborted) {
                    break;
                }
                
                const elapsedTime = Date.now() - startTime;
                if (elapsedTime > timeout * 0.5 && downloadedBytes < targetBytes * 0.1) {
                    throw new Error('下载速度过慢，提前终止');
                }
            }
            
            await reader.releaseLock();
            controller.abort();
            clearTimeout(timeoutId);
            
            const downloadTime = Date.now() - startTime;
            
            if (downloadTime === 0 || downloadedBytes === 0) {
                return {
                    success: false,
                    error: '下载数据量为0',
                    speed: null
                };
            }
            
            if (downloadedBytes < targetBytes * 0.1) {
                return {
                    success: false,
                    error: '下载数据量不足',
                    speed: null
                };
            }
            
            const speedMbps = (downloadedBytes * 8) / (downloadTime * 1000);
            
            return {
                success: true,
                speed: speedMbps,
                downloadedBytes,
                downloadTime
            };
        } catch (error) {
            clearTimeout(timeoutId);
            return {
                success: false,
                error: error.message,
                speed: null
            };
        }
    }
    
    function validateSpeedResult(result) {
        if (!result.success) return result;
        
        const { speed, downloadTime, downloadedBytes } = result;
        
        const calculatedSpeed = (downloadedBytes * 8) / (downloadTime * 1000);
        const deviation = Math.abs(speed - calculatedSpeed) / speed;
        
        if (deviation > 0.1) {
            return {
                ...result,
                speed: calculatedSpeed,
                warning: '速度计算结果已校正'
            };
        }
        
        if (speed > 1000) {
            return {
                success: false,
                error: '速度异常偏高',
                speed: null
            };
        }
        
        if (speed < 0.01) {
            return {
                success: false,
                error: '速度异常偏低',
                speed: null
            };
        }
        
        return result;
    }

    function parseCIDRFormat(cidrString) {
        try {
            const [network, prefixLength] = cidrString.split('/');
            const prefix = parseInt(prefixLength);
            
            if (isNaN(prefix) || prefix < 8 || prefix > 32) {
                return null;
            }
            
            const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            if (!ipRegex.test(network)) {
                return null;
            }
            
            const octets = network.split('.').map(Number);
            for (const octet of octets) {
                if (octet < 0 || octet > 255) {
                    return null;
                }
            }
            
            return {
                network: network,
                prefixLength: prefix,
                type: 'cidr'
            };
        } catch (error) {
            return null;
        }
    }

    function generateIPsFromCIDR(cidr, maxIPs = 100) {
        try {
            const [network, prefixLength] = cidr.split('/');
            const prefix = parseInt(prefixLength);

            const ipToInt = (ip) => {
                return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
            };

            const intToIP = (int) => {
                return [
                    (int >>> 24) & 255,
                    (int >>> 16) & 255,
                    (int >>> 8) & 255,
                    int & 255
                ].join('.');
            };

            const networkInt = ipToInt(network);
            const hostBits = 32 - prefix;
            const numHosts = Math.pow(2, hostBits);

            if (numHosts <= 2) {
                return [];
            }

            const maxHosts = numHosts - 2;
            const actualCount = Math.min(maxIPs, maxHosts);
            const ips = new Set();

            if (maxHosts <= 0) {
                return [];
            }

            let attempts = 0;
            const maxAttempts = actualCount * 10;

            while (ips.size < actualCount && attempts < maxAttempts) {
                const randomOffset = Math.floor(Math.random() * maxHosts) + 1;
                const randomIP = intToIP(networkInt + randomOffset);
                ips.add(randomIP);
                attempts++;
            }

            return Array.from(ips);
        } catch (error) {
            return [];
        }
    }

    async function GetCFIPs(ipSource = 'official', targetPort = '443', maxCount = 50) {
        try {
            let response;
            if (ipSource === 'as13335') {
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt');
            } else if (ipSource === 'as209242') {
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt');
            } else if (ipSource === 'as24429') {
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24429/ipv4-aggregated.txt');
            } else if (ipSource === 'as35916') {
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35916/ipv4-aggregated.txt');
            } else if (ipSource === 'as199524') {
                response = await fetch('https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199524/ipv4-aggregated.txt');
            } else {
                response = await fetch('https://www.cloudflare.com/ips-v4/');
            }

            const text = response.ok ? await response.text() : '';
            const cidrs = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));

            const allIPs = new Set();
            
            for (const cidr of cidrs) {
                const cidrInfo = parseCIDRFormat(cidr.trim());
                if (!cidrInfo) continue;
                
                const ipsFromCIDR = generateIPsFromCIDR(cidr.trim(), Math.ceil(maxCount / cidrs.length));
                ipsFromCIDR.forEach(ip => allIPs.add(ip + ':' + targetPort));
            }

            const ipArray = Array.from(allIPs);
            const targetCount = Math.min(maxCount, ipArray.length);
            
            if (ipArray.length > targetCount) {
                const shuffled = [...ipArray].sort(() => 0.5 - Math.random());
                return shuffled.slice(0, targetCount);
            }
            
            return ipArray;

        } catch (error) {
            return [];
        }
    }

    function parseProxyIPLine(line, targetPort) {
        try {
            line = line.trim();
            if (!line) return null;

            const cidrInfo = parseCIDRFormat(line);
            if (cidrInfo) {
                const ips = generateIPsFromCIDR(line, 10);
                return ips.length > 0 ? ips.map(ip => ip + ':' + targetPort) : null;
            }

            let ip = '';
            let port = targetPort;
            let comment = '';

            if (line.includes('#')) {
                const parts = line.split('#');
                const mainPart = parts[0].trim();
                comment = parts[1].trim();

                if (mainPart.includes(':')) {
                    const ipPortParts = mainPart.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        return null;
                    }
                } else {
                    ip = mainPart;
                }
            } else {
                if (line.includes(':')) {
                    const ipPortParts = line.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                        port = ipPortParts[1].trim();
                    } else {
                        return null;
                    }
                } else {
                    ip = line;
                }
            }

            if (!isValidIP(ip)) {
                return null;
            }

            const portNum = parseInt(port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                return null;
            }

            if (comment) {
                return ip + ':' + port + '#' + comment;
            } else {
                return ip + ':' + port;
            }

        } catch (error) {
            return null;
        }
    }

    function isValidIP(ip) {
        const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const match = ip.match(ipRegex);
        
        if (!match) return false;
        
        for (let i = 1; i <= 4; i++) {
            const num = parseInt(match[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }
        
        return true;
    }

    const url = new URL(request.url);
    
    if (request.method === "POST") {
        if (!sessionResult.valid) {
            return new Response(JSON.stringify({ error: '未授权访问' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (!env.SJ) return new Response("未绑定KV空间", { status: 400 });

        try {
            const contentType = request.headers.get('Content-Type');

            if (contentType && contentType.includes('application/json')) {
                const data = await request.json();
                const action = url.searchParams.get('action') || 'save';

                if (!data.ips || !Array.isArray(data.ips)) {
                    return new Response(JSON.stringify({ error: 'Invalid IP list' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                if (action === 'replace-cf' || action === 'append-cf') {
                    const cfContent = data.ips.join('\n');
                    
                    if (cfContent.length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({
                            error: '内容过大，超过KV存储限制（24MB）'
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }

                    if (action === 'replace-cf') {
                        await env.SJ.put(KC, cfContent);
                        yx = data.ips;
                        if (cc) {
                            cc.yx = [...data.ips];
                            cc.ct = Date.now();
                        }
                        const response = new Response(JSON.stringify({
                            success: true,
                            message: `成功替换优选IP列表，保存 ${data.ips.length} 个IP并立即生效`
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    } else {
                        const existingContent = await env.SJ.get(KC) || '';
                        const newContent = existingContent ? existingContent + '\n' + cfContent : cfContent;
                        
                        if (newContent.length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({
                                error: '追加后内容过大，超过KV存储限制（24MB）'
                            }), {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                        
                        await env.SJ.put(KC, newContent);
                        const newIPs = newContent.split('\n').filter(ip => ip.trim());
                        yx = newIPs;
                        if (cc) {
                            cc.yx = [...newIPs];
                            cc.ct = Date.now();
                        }
                        const response = new Response(JSON.stringify({
                            success: true,
                            message: `成功追加优选IP列表，新增 ${data.ips.length} 个IP并立即生效`
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    }
                }
                else if (action === 'replace-fd' || action === 'append-fd') {
                    const fdContent = data.ips.join('\n');
                    
                    if (fdContent.length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({
                            error: '内容过大，超过KV存储限制（24MB）'
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }

                    if (action === 'replace-fd') {
                        await env.SJ.put(KD, fdContent);
                        fdc = data.ips;
                        if (cc) {
                            cc.fdc = [...data.ips];
                            cc.ct = Date.now();
                        }
                        const response = new Response(JSON.stringify({
                            success: true,
                            message: `成功替换反代IP列表，保存 ${data.ips.length} 个IP并立即生效`
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    } else {
                        const existingContent = await env.SJ.get(KD) || '';
                        const newContent = existingContent ? existingContent + '\n' + fdContent : fdContent;
                        
                        if (newContent.length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({
                                error: '追加后内容过大，超过KV存储限制（24MB）'
                            }), {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' }
                            });
                        }
                        
                        await env.SJ.put(KD, newContent);
                        const newIPs = newContent.split('\n').filter(ip => ip.trim());
                        fdc = newIPs;
                        if (cc) {
                            cc.fdc = [...newIPs];
                            cc.ct = Date.now();
                        }
                        const response = new Response(JSON.stringify({
                            success: true,
                            message: `成功追加反代IP列表，新增 ${data.ips.length} 个IP并立即生效`
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    }
                } else {
                    const response = new Response(JSON.stringify({ error: '未知的操作类型' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                    if (sessionResult.refreshed) {
                        response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                    }
                    return response;
                }
            } else {
                const content = await request.text();
                await env.SJ.put(txt, content);
                const response = new Response("保存成功");
                if (sessionResult.refreshed) {
                    response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                }
                return response;
            }

        } catch (error) {
            const response = new Response(JSON.stringify({
                error: '操作失败: ' + error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
            if (sessionResult.refreshed) {
                response.headers.set('Set-Cookie', setSessionCookie(sessionId));
            }
            return response;
        }
    }

    if (url.searchParams.get('loadIPs')) {
        if (!sessionResult.valid) {
            return new Response(JSON.stringify({ error: '未授权访问' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const ipSource = url.searchParams.get('loadIPs');
        const port = url.searchParams.get('port') || '443';
        const count = parseInt(url.searchParams.get('count')) || 50;
        const ips = await GetCFIPs(ipSource, port, count);

        const response = new Response(JSON.stringify({ ips }), {
            headers: {
                'Content-Type': 'application/json',
            },
        });
        
        if (sessionResult.refreshed) {
            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
        }
        
        return response;
    }

    let content = '';
    let hasKV = !!env.SJ;

    if (hasKV) {
        try {
            content = await env.SJ.get(txt) || '';
        } catch (error) {
            content = '读取数据时发生错误: ' + error.message;
        }
    }

    const cfIPs = [];
    const isChina = country === 'CN';
    const countryDisplayClass = isChina ? '' : 'proxy-warning';
    const countryDisplayText = isChina ? `${country}` : `${country} ⚠️`;

    const html = `<!DOCTYPE html>
<html>
<head>
<title>Cloudflare IP优选</title>
<style>
    body {
        width: 80%;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
        padding: 20px;
    }
    .header-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        position: relative;
    }
    .page-title {
        text-align: center;
        flex: 1;
        margin: 0;
    }
    .ip-list {
        background-color: #f5f5f5;
        padding: 10px;
        border-radius: 5px;
        max-height: 400px;
        overflow-y: auto;
    }
    .ip-item {
        margin: 2px 0;
        font-family: monospace;
    }
    .stats {
        background-color: #e3f2fd;
        padding: 15px;
        border-radius: 5px;
        margin: 20px 0;
    }
    .proxy-warning {
        color: #d32f2f !important;
        font-weight: bold !important;
        font-size: 1.1em;
    }
    .test-controls {
        margin: 20px 0;
        padding: 15px;
        background-color: #f9f9f9;
        border-radius: 5px;
    }
    .port-selector {
        margin: 10px 0;
    }
    .port-selector label {
        font-weight: bold;
        margin-right: 10px;
    }
    .port-selector select {
        padding: 5px 10px;
        font-size: 14px;
        border: 1px solid #ccc;
        border-radius: 3px;
    }
    .count-selector {
        margin: 10px 0;
    }
    .count-selector label {
        font-weight: bold;
        margin-right: 10px;
    }
    .count-selector input {
        padding: 5px 10px;
        font-size: 14px;
        border: 1px solid #ccc;
        border-radius: 3px;
        width: 80px;
    }
    .concurrency-selector {
        margin: 10px 0;
    }
    .concurrency-selector label {
        font-weight: bold;
        margin-right: 10px;
    }
    .concurrency-selector input {
        padding: 5px 10px;
        font-size: 14px;
        border: 1px solid #ccc;
        border-radius: 3px;
        width: 60px;
    }
    .custom-url-selector {
        margin: 10px 0;
    }
    .custom-url-selector label {
        font-weight: bold;
        margin-right: 10px;
    }
    .custom-url-selector input {
        padding: 5px 10px;
        font-size: 14px;
        border: 1px solid #ccc;
        border-radius: 3px;
        width: 400px;
    }
    .button-group {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 15px;
        justify-content: center;
    }
    .button-row {
        display: flex;
        gap: 10px;
        justify-content: center;
        width: 100%;
        margin: 5px 0;
    }
    .test-button {
        background-color: #4CAF50;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .test-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }
    .replace-cf-button {
        background-color: #2196F3;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .replace-cf-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }
    .replace-cf-button:not(:disabled):hover {
        background-color: #1976D2;
    }
    .append-cf-button {
        background-color: #FF9800;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .append-cf-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }
    .append-cf-button:not(:disabled):hover {
        background-color: #F57C00;
    }
    .replace-fd-button {
        background-color: #9C27B0;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .replace-fd-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }
    .replace-fd-button:not(:disabled):hover {
        background-color: #7B1FA2;
    }
    .append-fd-button {
        background-color: #E91E63;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .append-fd-button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
    }
    .append-fd-button:not(:disabled):hover {
        background-color: #C2185B;
    }
    .config-button {
        background-color: #607D8B;
        color: white;
        padding: 10px 20px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 14px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .config-button:hover {
        background-color: #455A64;
    }
    .home-button {
        background-color: #795548;
        color: white;
        padding: 10px 20px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 14px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        transition: background-color 0.3s;
    }
    .home-button:hover {
        background-color: #5D4037;
    }
    .message {
        padding: 10px;
        margin: 10px 0;
        border-radius: 4px;
        display: none;
    }
    .message.success {
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    .message.error {
        background-color: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
    }
    .progress {
        width: 100%;
        background-color: #f0f0f0;
        border-radius: 5px;
        margin: 10px 0;
    }
    .progress-bar {
        width: 0%;
        height: 20px;
        background-color: #4CAF50;
        border-radius: 5px;
        transition: width 0.3s;
    }
    .good-latency { color: #4CAF50; font-weight: bold; }
    .medium-latency { color: #FF9800; font-weight: bold; }
    .bad-latency { color: #f44336; font-weight: bold; }
    .good-speed { color: #2196F3; font-weight: bold; }
    .medium-speed { color: #FF9800; font-weight: bold; }
    .bad-speed { color: #f44336; font-weight: bold; }
    .show-more-section {
        text-align: center;
        margin: 10px 0;
        padding: 10px;
        background-color: #f0f0f0;
        border-radius: 5px;
    }
    .show-more-btn {
        background-color: #607D8B;
        color: white;
        padding: 8px 20px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
        transition: background-color 0.3s;
    }
    .show-more-btn:hover {
        background-color: #455A64;
    }
    .ip-display-info {
        font-size: 12px;
        color: #666;
        margin-bottom: 5px;
    }
    .auto-save-notice {
        background-color: #e8f5e8;
        border: 1px solid #4CAF50;
        border-radius: 5px;
        padding: 10px;
        margin: 10px 0;
        font-size: 14px;
        color: #2e7d32;
    }
    .local-file-info {
        background-color: #e8f4fd;
        border: 1px solid #b8daff;
        border-radius: 5px;
        padding: 10px;
        margin: 10px 0;
        font-size: 14px;
    }
    .local-file-info h4 {
        margin: 0 0 8px 0;
        color: #004085;
    }
    .local-file-stats {
        display: flex;
        gap: 15px;
        flex-wrap: wrap;
    }
    .local-file-stat {
        display: flex;
        flex-direction: column;
    }
    .local-file-stat label {
        font-weight: bold;
        color: #0056b3;
        font-size: 12px;
    }
    .local-file-stat span {
        font-size: 14px;
        color: #333;
    }
    .message.info {
        background-color: #d1ecf1;
        color: #0c5460;
        border: 1px solid #bee5eb;
    }
    #saved-files-select {
        max-width: 250px;
        min-width: 150px;
    }
    .file-management-buttons {
        display: flex;
        gap: 5px;
        margin-left: 10px;
    }
    .file-management-btn {
        padding: 6px 12px;
        font-size: 12px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        transition: background-color 0.3s;
    }
    .rename-btn {
        background-color: #ffc107;
        color: #212529;
    }
    .rename-btn:hover {
        background-color: #e0a800;
    }
    .delete-btn {
        background-color: #dc3545;
        color: white;
    }
    .delete-btn:hover {
        background-color: #c82333;
    }
    .file-management-btn:disabled {
        background-color: #6c757d;
        cursor: not-allowed;
    }
</style>
</head>
<body>
<div class="header-container">
    <button class="home-button" id="home-btn" onclick="goHome()">返回主页</button>
    <h1 class="page-title">在线优选工具</h1>
    <button class="config-button" id="config-btn" onclick="goConfig()">返回配置</button>
</div>

${!isChina ? `
<div style="background-color: #ffebee; border: 2px solid #f44336; border-radius: 8px; padding: 15px; margin: 15px 0; color: #c62828;">
    <h3 style="margin: 0 0 10px 0; color: #d32f2f; font-size: 1.2em; display: flex; align-items: center; gap: 8px;">🚨 代理检测警告</h3>
    <p style="margin: 8px 0; line-height: 1.5;"><strong>检测到您当前很可能处于代理/VPN环境中！</strong></p>
    <p style="margin: 8px 0; line-height: 1.5;">在代理状态下进行的优选测试结果将不准确，可能导致：</p>
    <ul style="margin: 10px 0 10px 20px; line-height: 1.6;">
        <li>延迟数据失真，无法反映真实网络状况</li>
        <li>优选出的在直连环境下表现不佳</li>
        <li>测试结果对实际使用场景参考价值有限</li>
    </ul>
    <p style="margin: 8px 0; line-height: 1.5;"><strong>建议操作：</strong>请关闭所有代理软件（VPN、科学上网工具等），确保处于直连网络环境后重新访问本页面。</p>
</div>
` : ''}

<div class="auto-save-notice">
    <strong>自动保存说明：</strong> 使用下方的"替换"或"追加"按钮后，IP列表将自动保存到配置中并立即生效，无需在配置管理页面再次保存。
</div>

<div class="stats">
    <h2>统计信息</h2>
    <p><strong>您的国家：</strong><span class="${countryDisplayClass}">${countryDisplayText}</span></p>
    <p><strong>获取到的IP总数：</strong><span id="ip-count">点击开始测试后加载</span></p>
    <p><strong>测试进度：</strong><span id="progress-text">未开始</span></p>
    <div class="progress">
        <div class="progress-bar" id="progress-bar"></div>
    </div>
</div>

<div class="test-controls">
    <div class="port-selector">
        <label for="ip-source-select">IP库：</label>
        <select id="ip-source-select">
            <option value="official">CF官方列表</option>
            <option value="as13335">AS13335列表</option>
            <option value="as209242">AS209242列表</option>
            <option value="as24429">AS24429列表(Alibaba)</option>
            <option value="as199524">AS199524列表(G-Core)</option>
            <option value="local">本地上传</option>
        </select>

        <label for="port-select" style="margin-left: 20px;">端口：</label>
        <select id="port-select">
            <option value="443">443</option>
            <option value="2053">2053</option>
            <option value="2083">2083</option>
            <option value="2087">2087</option>
            <option value="2096">2096</option>
            <option value="8443">8443</option>
        </select>

        <label for="local-file-input" style="margin-left: 20px;">本地上传：</label>
        <input type="file" id="local-file-input" accept=".txt,.json,.csv,.conf,.list,.yml,.yaml" style="display: none;" onchange="handleFileUpload(this.files)">
        <button class="test-button" id="upload-btn" onclick="document.getElementById('local-file-input').click()" style="padding: 8px 16px; font-size: 14px;">
            <i class="fas fa-upload"></i>
            选择文件
        </button>
    </div>
    
    <div class="port-selector">
        <label for="saved-files-select">已保存文件：</label>
        <select id="saved-files-select" onchange="handleSavedFileSelect(this)" style="padding: 5px 10px; font-size: 14px; min-width: 250px;">
            <option value="">--选择已保存文件--</option>
        </select>
        
        <div class="file-management-buttons">
            <button class="file-management-btn rename-btn" id="rename-btn" onclick="renameSavedFile()" disabled>
                <i class="fas fa-edit"></i>
                重命名
            </button>
            
            <button class="file-management-btn delete-btn" id="delete-btn" onclick="deleteSavedFile()" disabled>
                <i class="fas fa-trash"></i>
                删除
            </button>
        </div>
    </div>
    
    <div class="count-selector">
        <label for="count-input">测试数量：</label>
        <input type="number" id="count-input" value="50" min="1" max="1000">
        <span style="margin-left: 10px; color: #666; font-size: 12px;">从IP源中解析所有IP段并选择指定数量的IP进行测试</span>
    </div>
    
    <div class="concurrency-selector">
        <label for="concurrency-input">并发数量：</label>
        <input type="number" id="concurrency-input" value="6" min="1" max="20">
        <span style="margin-left: 10px; color: #666; font-size: 12px;">同时测试的IP数量，过高可能导致测试不准确</span>
    </div>
    
    <div class="custom-url-selector">
        <label for="custom-test-url">测速文件URL：</label>
        <input type="text" id="custom-test-url" placeholder="https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin" style="width: 500px;">
        <span style="margin-left: 10px; color: #666; font-size: 12px;">自定义下载测速文件地址</span>
    </div>
    
    <div class="button-group">
        <div class="button-row">
            <button class="test-button" id="test-btn" onclick="startTest()">开始测试延迟和速度</button>
        </div>
        <div class="button-row">
            <button class="replace-cf-button" id="replace-cf-btn" onclick="replaceCFIPs()" disabled>替换优选IP/域名列表</button>
            <button class="append-cf-button" id="append-cf-btn" onclick="appendCFIPs()" disabled>追加优选IP/域名列表</button>
        </div>
        <div class="button-row">
            <button class="replace-fd-button" id="replace-fd-btn" onclick="replaceFDIPs()" disabled>替换反代IP/域名列表</button>
            <button class="append-fd-button" id="append-fd-btn" onclick="appendFDIPs()" disabled>追加反代IP/域名列表</button>
        </div>
    </div>
    <div id="message" class="message"></div>
</div>

<h2>IP列表 <span id="result-count"></span></h2>
<div class="ip-display-info" id="ip-display-info"></div>
<div id="region-filter" style="margin: 15px 0; display: none;"></div>
<div class="ip-list" id="ip-list">
    <div class="ip-item">请选择端口和IP库，然后点击"开始测试延迟和速度"加载IP列表</div>
</div>
<div class="show-more-section" id="show-more-section" style="display: none;">
    <button class="show-more-btn" id="show-more-btn" onclick="toggleShowMore()">显示更多</button>
</div>

<script>
    const LATENCY_CALIBRATION_FACTOR = 0.25;
    
    function calibrateLatency(rawLatency) {
        return Math.max(1, Math.round(rawLatency * LATENCY_CALIBRATION_FACTOR));
    }

    const LocalStorageKeys = {
        SAVED_FILES: 'cf-ip-saved-files',
        FILE_PREFIX: 'cf-ip-file-'
    };

    let originalIPs = [];
    let testResults = [];
    let displayedResults = [];
    let showingAll = false;
    let currentDisplayType = 'loading';
    let cloudflareLocations = {};
    
    const StorageKeys = {
        PORT: 'cf-ip-test-port',
        IP_SOURCE: 'cf-ip-test-source',
        COUNT: 'cf-ip-test-count',
        CONCURRENCY: 'cf-ip-test-concurrency',
        TEST_URL: 'cf-ip-test-url'
    };
    
    function initializeLocalStorage() {
        if (!localStorage.getItem(LocalStorageKeys.SAVED_FILES)) {
            localStorage.setItem(LocalStorageKeys.SAVED_FILES, JSON.stringify([]));
        }
        updateSavedFilesSelect();
    }

    function updateSavedFilesSelect() {
        const savedFilesSelect = document.getElementById('saved-files-select');
        const renameBtn = document.getElementById('rename-btn');
        const deleteBtn = document.getElementById('delete-btn');
        
        const savedFiles = JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES) || '[]');
        
        savedFilesSelect.innerHTML = '<option value="">--选择已保存文件--</option>';
        
        savedFiles.forEach(file => {
            const option = document.createElement('option');
            option.value = file.id;
            option.textContent = \`\${file.name} (\${file.ipCount}个IP, \${new Date(file.timestamp).toLocaleDateString()})\`;
            savedFilesSelect.appendChild(option);
        });
        
        updateFileManagementButtons();
    }

    function updateFileManagementButtons() {
        const savedFilesSelect = document.getElementById('saved-files-select');
        const renameBtn = document.getElementById('rename-btn');
        const deleteBtn = document.getElementById('delete-btn');
        
        const hasSelection = savedFilesSelect.value !== '';
        renameBtn.disabled = !hasSelection;
        deleteBtn.disabled = !hasSelection;
    }

    function handleSavedFileSelect(select) {
        updateFileManagementButtons();
        if (select.value) {
            document.getElementById('ip-source-select').value = 'local';
            loadSavedFile(select.value);
        }
    }

    function parseCIDRFormat(cidrString) {
        try {
            const [network, prefixLength] = cidrString.split('/');
            const prefix = parseInt(prefixLength);
            
            if (isNaN(prefix) || prefix < 8 || prefix > 32) {
                return null;
            }
            
            const ipRegex = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/;
            if (!ipRegex.test(network)) {
                return null;
            }
            
            const octets = network.split('.').map(Number);
            for (const octet of octets) {
                if (octet < 0 || octet > 255) {
                    return null;
                }
            }
            
            return {
                network: network,
                prefixLength: prefix,
                type: 'cidr'
            };
        } catch (error) {
            return null;
        }
    }

    function generateIPsFromCIDR(cidr, maxIPs = 100) {
        try {
            const [network, prefixLength] = cidr.split('/');
            const prefix = parseInt(prefixLength);

            const ipToInt = (ip) => {
                return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
            };

            const intToIP = (int) => {
                return [
                    (int >>> 24) & 255,
                    (int >>> 16) & 255,
                    (int >>> 8) & 255,
                    int & 255
                ].join('.');
            };

            const networkInt = ipToInt(network);
            const hostBits = 32 - prefix;
            const numHosts = Math.pow(2, hostBits);

            if (numHosts <= 2) {
                return [];
            }

            const maxHosts = numHosts - 2;
            const actualCount = Math.min(maxIPs, maxHosts);
            const ips = new Set();

            if (maxHosts <= 0) {
                return [];
            }

            let attempts = 0;
            const maxAttempts = actualCount * 10;

            while (ips.size < actualCount && attempts < maxAttempts) {
                const randomOffset = Math.floor(Math.random() * maxHosts) + 1;
                const randomIP = intToIP(networkInt + randomOffset);
                ips.add(randomIP);
                attempts++;
            }

            return Array.from(ips);
        } catch (error) {
            return [];
        }
    }

    function handleFileUpload(files) {
        if (files.length === 0) return;
        
        const file = files[0];
        const reader = new FileReader();
        
        reader.onload = function(e) {
            const content = e.target.result;
            const fileName = file.name.replace(/\\.[^/.]+$/, "");
            const targetPort = document.getElementById('port-select').value;
            
            const parsedIPs = parseFileContent(content, targetPort);
            
            if (parsedIPs.length === 0) {
                showMessage('未能在文件中找到有效的IP地址', 'error');
                return;
            }
            
            saveFileToLocalStorage(fileName, parsedIPs, content);
            
            document.getElementById('ip-source-select').value = 'local';
            
            loadIPsFromArray(parsedIPs);
            
            showFileLoadInfo(file.name, parsedIPs.length, file.size);
            showMessage(\`成功从文件 "\${file.name}" 加载 \${parsedIPs.length} 个IP地址\`, 'success');
        };
        
        reader.onerror = function() {
            showMessage('文件读取失败', 'error');
        };
        
        reader.readAsText(file);
    }

    function parseFileContent(content, targetPort) {
        const lines = content.split('\\n');
        const ips = new Set();
        const userCount = parseInt(document.getElementById('count-input').value) || 50;
        
        lines.forEach(line => {
            line = line.trim();
            if (!line || line.startsWith('#') || line.startsWith('//')) return;
            
            const cidrInfo = parseCIDRFormat(line);
            if (cidrInfo) {
                const maxIPsPerCIDR = Math.ceil(userCount / lines.length);
                const ipsFromCIDR = generateIPsFromCIDR(line, maxIPsPerCIDR);
                ipsFromCIDR.forEach(ip => {
                    const formattedIP = \`\${ip}:\${targetPort}\`;
                    ips.add(formattedIP);
                });
                return;
            }
            
            const parsedIP = parseIPLine(line, targetPort);
            if (parsedIP) {
                if (Array.isArray(parsedIP)) {
                    parsedIP.forEach(ip => ips.add(ip));
                } else {
                    ips.add(parsedIP);
                }
            }
        });
        
        const ipArray = Array.from(ips);
        return userCount < ipArray.length ? ipArray.slice(0, userCount) : ipArray;
    }

    function parseIPLine(line, targetPort) {
        try {
            let ip = '';
            let port = targetPort;
            let comment = '';

            let mainPart = line;
            if (line.includes('#')) {
                const parts = line.split('#');
                mainPart = parts[0].trim();
                comment = parts.slice(1).join('#').trim();
            }

            if (mainPart.includes(':')) {
                const parts = mainPart.split(':');
                if (parts.length === 2) {
                    ip = parts[0].trim();
                    port = parts[1].trim();
                } else {
                    return null;
                }
            } else {
                ip = mainPart.trim();
            }

            if (!isValidIP(ip)) {
                return null;
            }

            const portNum = parseInt(port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                return null;
            }

            if (comment) {
                return \`\${ip}:\${port}#\${comment}\`;
            } else {
                return \`\${ip}:\${port}\`;
            }

        } catch (error) {
            return null;
        }
    }

    function isValidIP(ip) {
        const ipv4Regex = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/;
        const match = ip.match(ipv4Regex);
        
        if (match) {
            for (let i = 1; i <= 4; i++) {
                const num = parseInt(match[i]);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        }
        
        return false;
    }

    function saveFileToLocalStorage(fileName, ips, originalContent) {
        const fileId = 'file_' + Date.now();
        const fileData = {
            id: fileId,
            name: fileName,
            ips: ips,
            content: originalContent,
            ipCount: ips.length,
            timestamp: Date.now()
        };
        
        localStorage.setItem(LocalStorageKeys.FILE_PREFIX + fileId, JSON.stringify(fileData));
        
        const savedFiles = JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES) || '[]');
        savedFiles.push({
            id: fileId,
            name: fileName,
            ipCount: ips.length,
            timestamp: Date.now()
        });
        
        localStorage.setItem(LocalStorageKeys.SAVED_FILES, JSON.stringify(savedFiles));
        updateSavedFilesSelect();
        
        document.getElementById('saved-files-select').value = fileId;
        updateFileManagementButtons();
    }

    function loadSavedFile(fileId) {
        if (!fileId) return;
        
        const fileData = localStorage.getItem(LocalStorageKeys.FILE_PREFIX + fileId);
        if (!fileData) {
            showMessage('文件不存在', 'error');
            return;
        }
        
        const parsedData = JSON.parse(fileData);
        const currentPort = document.getElementById('port-select').value;
        
        const updatedIPs = parsedData.ips.map(ip => updateIPPort(ip, currentPort));
        
        document.getElementById('ip-source-select').value = 'local';
        
        loadIPsFromArray(updatedIPs);
        
        showMessage(\`已加载文件 "\${parsedData.name}"，共 \${parsedData.ips.length} 个IP地址\`, 'success');
    }

    function updateIPPort(ipString, newPort) {
        try {
            let ip = '';
            let port = newPort;
            let comment = '';

            if (ipString.includes('#')) {
                const parts = ipString.split('#');
                const mainPart = parts[0].trim();
                comment = parts[1].trim();

                if (mainPart.includes(':')) {
                    const ipPortParts = mainPart.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                    } else {
                        return ipString;
                    }
                } else {
                    ip = mainPart;
                }
            } else {
                if (ipString.includes(':')) {
                    const ipPortParts = ipString.split(':');
                    if (ipPortParts.length === 2) {
                        ip = ipPortParts[0].trim();
                    } else {
                        return ipString;
                    }
                } else {
                    ip = ipString;
                }
            }

            if (comment) {
                return \`\${ip}:\${port}#\${comment}\`;
            } else {
                return \`\${ip}:\${port}\`;
            }
        } catch (error) {
            return ipString;
        }
    }

    function loadIPsFromArray(ips) {
        originalIPs = ips;
        testResults = [];
        displayedResults = [];
        showingAll = false;
        currentDisplayType = 'loading';
        
        document.getElementById('ip-count').textContent = ips.length + ' 个';
        
        displayLoadedIPs();
        
        document.getElementById('test-btn').disabled = false;
        
        updateButtonStates();
    }

    function renameSavedFile() {
        const savedFilesSelect = document.getElementById('saved-files-select');
        const fileId = savedFilesSelect.value;
        
        if (!fileId) {
            showMessage('请先选择一个文件', 'error');
            return;
        }
        
        const fileData = localStorage.getItem(LocalStorageKeys.FILE_PREFIX + fileId);
        if (!fileData) {
            showMessage('文件不存在', 'error');
            return;
        }
        
        const parsedData = JSON.parse(fileData);
        const newName = prompt('请输入新的文件名：', parsedData.name);
        
        if (!newName || newName.trim() === '') return;
        
        parsedData.name = newName.trim();
        
        localStorage.setItem(LocalStorageKeys.FILE_PREFIX + fileId, JSON.stringify(parsedData));
        
        const savedFiles = JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES) || '[]');
        const fileIndex = savedFiles.findIndex(file => file.id === fileId);
        if (fileIndex !== -1) {
            savedFiles[fileIndex].name = newName.trim();
            localStorage.setItem(LocalStorageKeys.SAVED_FILES, JSON.stringify(savedFiles));
        }
        
        updateSavedFilesSelect();
        
        document.getElementById('saved-files-select').value = fileId;
        updateFileManagementButtons();
        
        showMessage('文件名已更新', 'success');
    }

    function deleteSavedFile() {
        const savedFilesSelect = document.getElementById('saved-files-select');
        const fileId = savedFilesSelect.value;
        
        if (!fileId) {
            showMessage('请先选择一个文件', 'error');
            return;
        }
        
        if (!confirm('确定要删除这个文件吗？此操作不可撤销。')) return;
        
        const savedFiles = JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES) || '[]');
        const filteredFiles = savedFiles.filter(file => file.id !== fileId);
        localStorage.setItem(LocalStorageKeys.SAVED_FILES, JSON.stringify(filteredFiles));
        
        localStorage.removeItem(LocalStorageKeys.FILE_PREFIX + fileId);
        
        updateSavedFilesSelect();
        updateFileManagementButtons();
        
        showMessage('文件已删除', 'success');
    }

    function showFileLoadInfo(fileName, ipCount, fileSize) {
        const fileInfoDiv = document.createElement('div');
        fileInfoDiv.className = 'local-file-info';
        fileInfoDiv.innerHTML = \`
            <h4>📁 文件加载成功</h4>
            <div class="local-file-stats">
                <div class="local-file-stat">
                    <label>文件名:</label>
                    <span>\${fileName}</span>
                </div>
                <div class="local-file-stat">
                    <label>IP数量:</label>
                    <span>\${ipCount} 个</span>
                </div>
                <div class="local-file-stat">
                    <label>文件大小:</label>
                    <span>\${(fileSize / 1024).toFixed(2)} KB</span>
                </div>
            </div>
            <div style="margin-top: 8px; font-size: 12px; color: #666;">
                IP列表已加载完成，点击"开始测试"按钮开始测试
            </div>
        \`;
        
        const testControls = document.querySelector('.test-controls');
        const existingInfo = document.querySelector('.local-file-info');
        if (existingInfo) {
            existingInfo.remove();
        }
        testControls.parentNode.insertBefore(fileInfoDiv, testControls);
    }
    
    async function loadCloudflareLocations() {
        try {
            const response = await fetch('https://speed.cloudflare.com/locations');
            if (response.ok) {
                const locations = await response.json();
                cloudflareLocations = {};
                locations.forEach(location => {
                    cloudflareLocations[location.iata] = location;
                });
            }
        } catch (error) {
        }
    }
    
    function initializeSettings() {
        const portSelect = document.getElementById('port-select');
        const ipSourceSelect = document.getElementById('ip-source-select');
        const countInput = document.getElementById('count-input');
        const concurrencyInput = document.getElementById('concurrency-input');
        const customTestUrl = document.getElementById('custom-test-url');
        
        const savedPort = localStorage.getItem(StorageKeys.PORT);
        const savedIPSource = localStorage.getItem(StorageKeys.IP_SOURCE);
        const savedCount = localStorage.getItem(StorageKeys.COUNT);
        const savedConcurrency = localStorage.getItem(StorageKeys.CONCURRENCY);
        const savedTestUrl = localStorage.getItem(StorageKeys.TEST_URL);
        
        if (savedPort && portSelect.querySelector(\`option[value="\${savedPort}"]\`)) {
            portSelect.value = savedPort;
        } else {
            portSelect.value = '8443';
        }
        
        if (savedIPSource && ipSourceSelect.querySelector(\`option[value="\${savedIPSource}"]\`)) {
            ipSourceSelect.value = savedIPSource;
        } else {
            ipSourceSelect.value = 'official';
        }
        
        if (savedCount) {
            countInput.value = savedCount;
        } else {
            countInput.value = '50';
        }
        
        if (savedConcurrency) {
            concurrencyInput.value = savedConcurrency;
        } else {
            concurrencyInput.value = '6';
        }
        
        if (savedTestUrl) {
            customTestUrl.value = savedTestUrl;
        }
        
        portSelect.addEventListener('change', function() {
            localStorage.setItem(StorageKeys.PORT, this.value);
            if (originalIPs.length > 0) {
                const newPort = this.value;
                const updatedIPs = originalIPs.map(ip => updateIPPort(ip, newPort));
                loadIPsFromArray(updatedIPs);
            }
        });
        
        ipSourceSelect.addEventListener('change', function() {
            localStorage.setItem(StorageKeys.IP_SOURCE, this.value);
        });
        
        countInput.addEventListener('change', function() {
            localStorage.setItem(StorageKeys.COUNT, this.value);
        });
        
        concurrencyInput.addEventListener('change', function() {
            localStorage.setItem(StorageKeys.CONCURRENCY, this.value);
        });
        
        customTestUrl.addEventListener('change', function() {
            localStorage.setItem(StorageKeys.TEST_URL, this.value);
        });
    }
    
    document.addEventListener('DOMContentLoaded', async function() {
        await loadCloudflareLocations();
        initializeSettings();
        initializeLocalStorage();
    });
    
    function shuffleArray(array) {
        const newArray = [...array];
        for (let i = newArray.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
        }
        return newArray;
    }
    
    function toggleShowMore() {
        if (currentDisplayType === 'testing') {
            return;
        }
        
        showingAll = !showingAll;
        
        if (currentDisplayType === 'loading') {
            displayLoadedIPs();
        } else if (currentDisplayType === 'results') {
            displayResults();
        }
    }
    
    function displayLoadedIPs() {
        const ipList = document.getElementById('ip-list');
        const showMoreSection = document.getElementById('show-more-section');
        const showMoreBtn = document.getElementById('show-more-btn');
        const ipDisplayInfo = document.getElementById('ip-display-info');
        
        if (originalIPs.length === 0) {
            ipList.innerHTML = '<div class="ip-item">加载IP列表失败，请重试</div>';
            showMoreSection.style.display = 'none';
            ipDisplayInfo.textContent = '';
            return;
        }
        
        const displayCount = showingAll ? originalIPs.length : Math.min(originalIPs.length, 16);
        const displayIPs = originalIPs.slice(0, displayCount);
        
        const randomInfo = currentDisplayType === 'loading' ? '（随机选择）' : '';
        
        if (originalIPs.length <= 16) {
            ipDisplayInfo.textContent = \`显示全部 \${originalIPs.length} 个IP\${randomInfo}\`;
            showMoreSection.style.display = 'none';
        } else {
            ipDisplayInfo.textContent = \`显示前 \${displayCount} 个IP，共加载 \${originalIPs.length} 个IP\${randomInfo}\`;
            if (currentDisplayType !== 'testing') {
                showMoreSection.style.display = 'block';
                showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
                showMoreBtn.disabled = false;
            } else {
                showMoreSection.style.display = 'none';
            }
        }
        
        ipList.innerHTML = displayIPs.map(ip => \`<div class="ip-item">\${ip}</div>\`).join('');
    }
    
    function showMessage(text, type = 'success') {
        const messageDiv = document.getElementById('message');
        messageDiv.textContent = text;
        messageDiv.className = \`message \${type}\`;
        messageDiv.style.display = 'block';
        
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 5000);
    }
    
    function updateButtonStates() {
        const replaceCfBtn = document.getElementById('replace-cf-btn');
        const appendCfBtn = document.getElementById('append-cf-btn');
        const replaceFdBtn = document.getElementById('replace-fd-btn');
        const appendFdBtn = document.getElementById('append-fd-btn');
        const hasResults = displayedResults.length > 0;
        
        replaceCfBtn.disabled = !hasResults;
        appendCfBtn.disabled = !hasResults;
        replaceFdBtn.disabled = !hasResults;
        appendFdBtn.disabled = !hasResults;
    }
    
    function disableAllButtons() {
        const testBtn = document.getElementById('test-btn');
        const replaceCfBtn = document.getElementById('replace-cf-btn');
        const appendCfBtn = document.getElementById('append-cf-btn');
        const replaceFdBtn = document.getElementById('replace-fd-btn');
        const appendFdBtn = document.getElementById('append-fd-btn');
        const configBtn = document.getElementById('config-btn');
        const homeBtn = document.getElementById('home-btn');
        const portSelect = document.getElementById('port-select');
        const ipSourceSelect = document.getElementById('ip-source-select');
        const countInput = document.getElementById('count-input');
        const concurrencyInput = document.getElementById('concurrency-input');
        const customTestUrl = document.getElementById('custom-test-url');
        
        testBtn.disabled = true;
        replaceCfBtn.disabled = true;
        appendCfBtn.disabled = true;
        replaceFdBtn.disabled = true;
        appendFdBtn.disabled = true;
        configBtn.disabled = true;
        homeBtn.disabled = true;
        portSelect.disabled = true;
        ipSourceSelect.disabled = true;
        countInput.disabled = true;
        concurrencyInput.disabled = true;
        customTestUrl.disabled = true;
    }
    
    function enableButtons() {
        const testBtn = document.getElementById('test-btn');
        const configBtn = document.getElementById('config-btn');
        const homeBtn = document.getElementById('home-btn');
        const portSelect = document.getElementById('port-select');
        const ipSourceSelect = document.getElementById('ip-source-select');
        const countInput = document.getElementById('count-input');
        const concurrencyInput = document.getElementById('concurrency-input');
        const customTestUrl = document.getElementById('custom-test-url');
        
        testBtn.disabled = false;
        configBtn.disabled = false;
        homeBtn.disabled = false;
        portSelect.disabled = false;
        ipSourceSelect.disabled = false;
        countInput.disabled = false;
        concurrencyInput.disabled = false;
        customTestUrl.disabled = false;
        updateButtonStates();
    }
    
    function formatIPForSave(result) {
        const port = document.getElementById('port-select').value;
        let ip = result.ip;
        let countryCode = result.locationCode || 'XX';
        let countryName = getCountryName(countryCode);
        
        return \`\${ip}:\${port}#\${countryName}|\${countryCode}\`;
    }
    
    function formatIPForFD(result) {
        const port = document.getElementById('port-select').value;
        let countryCode = result.locationCode || 'XX';
        let countryName = getCountryName(countryCode);
        return \`\${result.ip}:\${port}#\${countryName}\`;
    }
    
    function getCountryName(countryCode) {
        const countryMap = {
            'US': '美国', 'SG': '新加坡', 'DE': '德国', 'JP': '日本', 'KR': '韩国',
            'HK': '香港', 'TW': '台湾', 'GB': '英国', 'FR': '法国', 'IN': '印度',
            'BR': '巴西', 'CA': '加拿大', 'AU': '澳大利亚', 'NL': '荷兰', 'CH': '瑞士',
            'SE': '瑞典', 'IT': '意大利', 'ES': '西班牙', 'RU': '俄罗斯', 'ZA': '南非',
            'MX': '墨西哥', 'MY': '马来西亚', 'TH': '泰国', 'ID': '印度尼西亚', 'VN': '越南',
            'PH': '菲律宾', 'TR': '土耳其', 'SA': '沙特阿拉伯', 'AE': '阿联酋', 'EG': '埃及',
            'NG': '尼日利亚', 'IL': '以色列', 'PL': '波兰', 'UA': '乌克兰', 'CZ': '捷克',
            'RO': '罗马尼亚', 'GR': '希腊', 'PT': '葡萄牙', 'DK': '丹麦', 'FI': '芬兰',
            'NO': '挪威', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰', 'LU': '卢森堡',
            'CY': '塞浦路斯', 'MT': '马耳他', 'IS': '冰岛', 'CN': '中国'
        };
        return countryMap[countryCode] || countryCode;
    }
    
    async function saveIPs(action, formatFunction, buttonId, successMessage) {
        let ipsToSave = [];
        if (document.getElementById('region-filter') && document.getElementById('region-filter').style.display !== 'none') {
            ipsToSave = displayedResults;
        } else {
            ipsToSave = testResults;
        }
        
        if (ipsToSave.length === 0) {
            showMessage('没有可保存的IP结果', 'error');
            return;
        }
        
        const button = document.getElementById(buttonId);
        const originalText = button.textContent;
        
        disableAllButtons();
        button.textContent = '保存中...';
        
        try {
            const saveCount = Math.min(ipsToSave.length, 6);
            const ips = ipsToSave.slice(0, saveCount).map(result => formatFunction(result));
            
            const response = await fetch(\`?action=\${action}\`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ips })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showMessage(successMessage + '（已保存前' + saveCount + '个最优IP）', 'success');
            } else {
                showMessage(data.error || '保存失败', 'error');
            }
            
        } catch (error) {
            showMessage('保存失败: ' + error.message, 'error');
        } finally {
            button.textContent = originalText;
            enableButtons();
        }
    }
    
    async function replaceCFIPs() {
        await saveIPs('replace-cf', formatIPForSave, 'replace-cf-btn', '成功替换优选IP列表');
    }
    
    async function appendCFIPs() {
        await saveIPs('append-cf', formatIPForSave, 'append-cf-btn', '成功追加优选IP列表');
    }
    
    async function replaceFDIPs() {
        await saveIPs('replace-fd', formatIPForFD, 'replace-fd-btn', '成功替换反代IP列表');
    }
    
    async function appendFDIPs() {
        await saveIPs('append-fd', formatIPForFD, 'append-fd-btn', '成功追加反代IP列表');
    }
    
    function goConfig() {
        window.location.href = \`/admin\`;
    }
    
    function goHome() {
        window.location.href = \`/\`;
    }
    
    function isRetriableError(error) {
        if (!error) return false;
        
        const errorMessage = error.message || error.toString();
        const retryablePatterns = [
            'timeout', 'abort', 'network', 'fetch', 'failed',
            'load failed', 'connection', 'socket', 'reset'
        ];
        
        const nonRetryablePatterns = [
            'HTTP 4', 'HTTP 5', '404', '500', '502', '503',
            'certificate', 'SSL', 'TLS', 'CORS', 'blocked'
        ];
        
        const isRetryable = retryablePatterns.some(pattern => 
            errorMessage.toLowerCase().includes(pattern.toLowerCase())
        );
        
        const isNonRetryable = nonRetryablePatterns.some(pattern => 
            errorMessage.toLowerCase().includes(pattern.toLowerCase())
        );
        
        return isRetryable && !isNonRetryable;
    }
    
    async function smartRetry(operation, maxAttempts = 3, baseDelay = 200, timeout = 5000) {
        let lastError;
        
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            
            try {
                const result = await Promise.race([
                    operation(controller.signal),
                    new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('Operation timeout')), timeout)
                    )
                ]);
                
                clearTimeout(timeoutId);
                
                if (result && result.success !== false) {
                    return result;
                }
                
                if (result && result.error) {
                    if (result.error.includes('HTTP 4') || result.error.includes('HTTP 5')) {
                        return result;
                    }
                }
                
                lastError = result ? result.error : new Error('Operation failed');
                
            } catch (error) {
                clearTimeout(timeoutId);
                lastError = error;
                
                if (!error.message.includes('network') && 
                    !error.message.includes('timeout') && 
                    !error.message.includes('fetch')) {
                    throw error;
                }
            }
            
            if (attempt < maxAttempts) {
                const delay = baseDelay * Math.pow(2, attempt - 1) + Math.random() * 100;
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        
        throw lastError;
    }
    
    async function adaptiveSpeedTest(ip, port, calibratedLatency, customTestUrl) {
        if (calibratedLatency >= 1500) {
            return {
                success: false,
                error: '延迟过高，跳过测速',
                speed: null
            };
        }
        
        const testProfiles = {
            'excellent': { 
                size: 2 * 1024 * 1024,
                timeout: 8000,
                quickSize: 256 * 1024,
                quickTimeout: 4000
            },
            'good': { 
                size: 1 * 1024 * 1024,
                timeout: 10000,
                quickSize: 128 * 1024,
                quickTimeout: 4000
            },
            'fair': { 
                size: 512 * 1024,
                timeout: 12000,
                quickSize: 64 * 1024,
                quickTimeout: 5000
            },
            'poor': { 
                size: 256 * 1024,
                timeout: 15000,
                quickSize: 32 * 1024,
                quickTimeout: 6000
            }
        };
        
        let profile;
        if (calibratedLatency < 80) {
            profile = testProfiles.excellent;
        } else if (calibratedLatency < 300) {
            profile = testProfiles.good;
        } else if (calibratedLatency < 600) {
            profile = testProfiles.fair;
        } else {
            profile = testProfiles.poor;
        }
        
        const fallbackUrls = [
            'https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin',
            'https://speed.cloudflare.com/__down?bytes=8388608',
            'https://cachefly.cachefly.net/100mb.test',
            'https://proof.ovh.net/files/100Mb.dat'
        ];
        
        let testUrl = customTestUrl;
        if (!testUrl) {
            testUrl = fallbackUrls[0];
        }
        
        const quickResult = await smartRetry(
            async (signal) => {
                let result = await testDownloadSpeedWithSize(ip, port, profile.quickSize, profile.quickTimeout, testUrl, signal);
                
                if (!result.success && !customTestUrl) {
                    for (let i = 1; i < fallbackUrls.length && !result.success; i++) {
                        try {
                            result = await testDownloadSpeedWithSize(ip, port, profile.quickSize, profile.quickTimeout, fallbackUrls[i], signal);
                        } catch (e) {
                            continue;
                        }
                    }
                }
                return result;
            },
            2,
            200,
            profile.quickTimeout + 1000
        );
        
        if (!quickResult.success || quickResult.speed < 0.3) {
            return {
                success: false,
                error: '快速测速不达标',
                speed: null
            };
        }
        
        await new Promise(resolve => setTimeout(resolve, 200));
        
        const fullResult = await smartRetry(
            async (signal) => {
                let result = await testDownloadSpeedWithSize(ip, port, profile.size, profile.timeout, testUrl, signal);
                
                if (!result.success && !customTestUrl) {
                    for (let i = 1; i < fallbackUrls.length && !result.success; i++) {
                        try {
                            result = await testDownloadSpeedWithSize(ip, port, profile.size, profile.timeout, fallbackUrls[i], signal);
                        } catch (e) {
                            continue;
                        }
                    }
                }
                return result;
            },
            2,
            300,
            profile.timeout + 1000
        );
        
        return validateSpeedResult(fullResult);
    }
    
    async function testDownloadSpeedWithSize(ip, port, targetBytes, timeout, customTestUrl, abortSignal) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        if (abortSignal) {
            abortSignal.addEventListener('abort', () => controller.abort());
        }
        
        try {
            const startTime = Date.now();
            let downloadedBytes = 0;
            
            const testUrl = customTestUrl || \`https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin\`;
            
            const response = await fetch(testUrl, {
                signal: controller.signal,
                cf: {
                    resolveOverride: ip
                }
            });
            
            if (!response.ok) {
                throw new Error(\`HTTP \${response.status}\`);
            }
            
            const reader = response.body.getReader();
            const chunks = [];
            
            while (downloadedBytes < targetBytes) {
                const { done, value } = await reader.read();
                
                if (done) {
                    break;
                }
                
                chunks.push(value);
                downloadedBytes += value.length;
                
                if (downloadedBytes >= targetBytes) {
                    break;
                }
                
                if (controller.signal.aborted) {
                    break;
                }
                
                const elapsedTime = Date.now() - startTime;
                if (elapsedTime > timeout * 0.5 && downloadedBytes < targetBytes * 0.1) {
                    throw new Error('下载速度过慢，提前终止');
                }
            }
            
            await reader.releaseLock();
            controller.abort();
            clearTimeout(timeoutId);
            
            const downloadTime = Date.now() - startTime;
            
            if (downloadTime === 0 || downloadedBytes === 0) {
                return {
                    success: false,
                    error: '下载数据量为0',
                    speed: null
                };
            }
            
            if (downloadedBytes < targetBytes * 0.1) {
                return {
                    success: false,
                    error: '下载数据量不足',
                    speed: null
                };
            }
            
            const speedMbps = (downloadedBytes * 8) / (downloadTime * 1000);
            
            return {
                success: true,
                speed: speedMbps,
                downloadedBytes,
                downloadTime
            };
        } catch (error) {
            clearTimeout(timeoutId);
            return {
                success: false,
                error: error.message,
                speed: null
            };
        }
    }
    
    function validateSpeedResult(result) {
        if (!result.success) return result;
        
        const { speed, downloadTime, downloadedBytes } = result;
        
        const calculatedSpeed = (downloadedBytes * 8) / (downloadTime * 1000);
        const deviation = Math.abs(speed - calculatedSpeed) / speed;
        
        if (deviation > 0.1) {
            return {
                ...result,
                speed: calculatedSpeed,
                warning: '速度计算结果已校正'
            };
        }
        
        if (speed > 1000) {
            return {
                success: false,
                error: '速度异常偏高',
                speed: null
            };
        }
        
        if (speed < 0.01) {
            return {
                success: false,
                error: '速度异常偏低',
                speed: null
            };
        }
        
        return result;
    }
    
    async function testIP(ip, port, customTestUrl) {
        const timeout = 3000;
        
        const parsedIP = parseIPFormat(ip, port);
        if (!parsedIP) {
            return null;
        }
        
        const latencyResult = await smartRetry(
            (signal) => singleLatencyTest(parsedIP.host, parsedIP.port, timeout, signal),
            2,
            200,
            timeout + 1000
        );
        
        if (!latencyResult) {
            return null;
        }
        
        const locationCode = cloudflareLocations[latencyResult.colo] ? 
            cloudflareLocations[latencyResult.colo].cca2 : latencyResult.colo;
        const countryName = getCountryName(locationCode);
        
        const typeText = latencyResult.type === 'official' ? '官方优选' : '反代优选';
        
        const calibratedLatency = calibrateLatency(latencyResult.latency);
        
        let downloadSpeed = null;
        if (calibratedLatency < 1500) {
            try {
                await new Promise(resolve => setTimeout(resolve, 50));
                const downloadResult = await adaptiveSpeedTest(
                    parsedIP.host, 
                    parsedIP.port, 
                    calibratedLatency, 
                    customTestUrl
                );
                if (downloadResult.success) {
                    downloadSpeed = downloadResult.speed;
                }
            } catch (error) {
            }
        }
        
        let display;
        if (latencyResult.type === 'official') {
            if (downloadSpeed !== null) {
                display = \`\${parsedIP.host}:\${parsedIP.port}#\${countryName}|\${locationCode} \${typeText} 延迟:\${calibratedLatency}ms 速度:\${downloadSpeed.toFixed(2)}Mbps\`;
            } else {
                display = \`\${parsedIP.host}:\${parsedIP.port}#\${countryName}|\${locationCode} \${typeText} 延迟:\${calibratedLatency}ms 速度:N/A\`;
            }
        } else {
            if (downloadSpeed !== null) {
                display = \`\${parsedIP.host}:\${parsedIP.port}#\${countryName} \${typeText} 延迟:\${calibratedLatency}ms 速度:\${downloadSpeed.toFixed(2)}Mbps\`;
            } else {
                display = \`\${parsedIP.host}:\${parsedIP.port}#\${countryName} \${typeText} 延迟:\${calibratedLatency}ms 速度:N/A\`;
            }
        }
        
        return {
            ip: parsedIP.host,
            port: parsedIP.port,
            latency: latencyResult.latency,
            calibratedLatency: calibratedLatency,
            speed: downloadSpeed,
            colo: latencyResult.colo,
            type: latencyResult.type,
            locationCode: locationCode,
            comment: \`\${countryName} \${typeText}\`,
            display: display
        };
    }
    
    function parseIPFormat(ipString, defaultPort) {
        try {
            let host, port, comment;
            
            let mainPart = ipString;
            if (ipString.includes('#')) {
                const parts = ipString.split('#');
                mainPart = parts[0];
                comment = parts[1];
            }
            
            if (mainPart.includes(':')) {
                const parts = mainPart.split(':');
                host = parts[0];
                port = parseInt(parts[1]);
            } else {
                host = mainPart;
                port = parseInt(defaultPort);
            }
            
            if (!host || !port || isNaN(port)) {
                return null;
            }
            
            return {
                host: host.trim(),
                port: port,
                comment: comment ? comment.trim() : null
            };
        } catch (error) {
            return null;
        }
    }
    
    async function singleLatencyTest(ip, port, timeout, abortSignal) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        if (abortSignal) {
            abortSignal.addEventListener('abort', () => controller.abort());
        }
        
        const startTime = Date.now();
        
        try {
            const parts = ip.split('.').map(part => {
                const hex = parseInt(part, 10).toString(16);
                return hex.length === 1 ? '0' + hex : hex;
            });
            const nip = parts.join('');
            
            const response = await fetch(\`https://\${nip}.${nipDomain}:\${port}/cdn-cgi/trace\`, {
                signal: controller.signal,
                mode: 'cors'
            });
            
        clearTimeout(timeoutId);
        
        if (response.status === 200) {
            const latency = Date.now() - startTime;
            const responseText = await response.text();
            
            const traceData = parseTraceResponse(responseText);
            
            if (traceData && traceData.ip && traceData.colo) {
                const responseIP = traceData.ip;
                let ipType = 'official';
                
                if (responseIP.includes(':') || responseIP === ip) {
                    ipType = 'proxy';
                }
                
                return {
                    ip: ip,
                    port: port,
                    latency: latency,
                    colo: traceData.colo,
                    type: ipType,
                    responseIP: responseIP
                };
            }
        }
        
        return null;
        
    } catch (error) {
        clearTimeout(timeoutId);
        const latency = Date.now() - startTime;
        
        if (latency < timeout - 100) {
            return {
                ip: ip,
                port: port,
                latency: latency,
                colo: 'UNKNOWN',
                type: 'unknown',
                responseIP: null
            };
        }
        
        return null;
    }
}

function parseTraceResponse(responseText) {
    try {
        const lines = responseText.split('\\n');
        const data = {};
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (trimmedLine && trimmedLine.includes('=')) {
                const [key, value] = trimmedLine.split('=', 2);
                data[key] = value;
            }
        }
        
        return data;
    } catch (error) {
        return null;
    }
}

async function testIPsWithConcurrency(ips, port, maxConcurrency = 6, customTestUrl) {
    const results = [];
    const totalIPs = ips.length;
    let completedTests = 0;
    let activeWorkers = 0;
    let currentIndex = 0;
    
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    
    const workers = Array(Math.min(maxConcurrency, ips.length)).fill().map(async (_, workerId) => {
        while (currentIndex < ips.length) {
            const index = currentIndex++;
            if (index >= ips.length) break;
            
            const ip = ips[index];
            activeWorkers++;
            
            try {
                await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
                
                const result = await testIP(ip, port, customTestUrl);
                if (result) {
                    results.push(result);
                }
            } catch (error) {
            } finally {
                activeWorkers--;
                completedTests++;
                
                const progress = (completedTests / totalIPs) * 100;
                progressBar.style.width = progress + '%';
                progressText.textContent = \`\${completedTests}/\${totalIPs} (\${progress.toFixed(1)}%) - 有效IP: \${results.length} - 并发: \${activeWorkers}\`;
                
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    });
    
    await Promise.all(workers);
    return results;
}

function displayResults() {
    const ipList = document.getElementById('ip-list');
    const resultCount = document.getElementById('result-count');
    const showMoreSection = document.getElementById('show-more-section');
    const showMoreBtn = document.getElementById('show-more-btn');
    const ipDisplayInfo = document.getElementById('ip-display-info');
    
    if (testResults.length === 0) {
        ipList.innerHTML = '<div class="ip-item">未找到有效的IP</div>';
        resultCount.textContent = '';
        ipDisplayInfo.textContent = '';
        showMoreSection.style.display = 'none';
        displayedResults = [];
        updateButtonStates();
        return;
    }
    
    const maxDisplayCount = showingAll ? testResults.length : Math.min(testResults.length, 16);
    displayedResults = testResults.slice(0, maxDisplayCount);
    
    if (testResults.length <= 16) {
        resultCount.textContent = '(共测试出 ' + testResults.length + ' 个有效IP)';
        ipDisplayInfo.textContent = '显示全部 ' + testResults.length + ' 个测试结果';
        showMoreSection.style.display = 'none';
    } else {
        resultCount.textContent = '(共测试出 ' + testResults.length + ' 个有效IP)';
        ipDisplayInfo.textContent = '显示前 ' + maxDisplayCount + ' 个测试结果，共 ' + testResults.length + ' 个有效IP';
        showMoreSection.style.display = 'block';
        showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
        showMoreBtn.disabled = false;
    }
    
    const resultsHTML = displayedResults.map(result => {
        const calibratedLatency = result.calibratedLatency || calibrateLatency(result.latency);
        
        let latencyClass = 'good-latency';
        if (calibratedLatency > 200) latencyClass = 'bad-latency';
        else if (calibratedLatency > 100) latencyClass = 'medium-latency';
        
        let speedClass = 'good-speed';
        let speedText = '速度:N/A';
        if (result.speed !== null) {
            if (result.speed < 5) speedClass = 'bad-speed';
            else if (result.speed < 10) speedClass = 'medium-speed';
            speedText = \`速度:\${result.speed.toFixed(2)}Mbps\`;
        }
        
        return \`<div class="ip-item"><span class="\${latencyClass}">\${result.display.split(' 延迟:')[0]} 延迟:\${calibratedLatency}ms</span> <span class="\${speedClass}">\${speedText}</span></div>\`;
    }).join('');
    
    ipList.innerHTML = resultsHTML;
    updateButtonStates();
}

function createRegionFilter() {
    const uniqueRegions = [...new Set(testResults.map(result => result.locationCode))];
    uniqueRegions.sort();
    
    const filterContainer = document.getElementById('region-filter');
    if (!filterContainer) return;
    
    if (uniqueRegions.length === 0) {
        filterContainer.style.display = 'none';
        return;
    }
    
    let filterHTML = '<h3>地区筛选：</h3><div class="region-buttons">';
    filterHTML += '<button class="region-btn active" data-region="all">全部 (' + testResults.length + ')</button>';
    
    uniqueRegions.forEach(region => {
        const count = testResults.filter(r => r.locationCode === region).length;
        filterHTML += '<button class="region-btn" data-region="' + region + '">' + region + ' (' + count + ')</button>';
    });
    
    filterHTML += '</div>';
    filterContainer.innerHTML = filterHTML;
    filterContainer.style.display = 'block';
    
    document.querySelectorAll('.region-btn').forEach(button => {
        button.addEventListener('click', function() {
            document.querySelectorAll('.region-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            
            const selectedRegion = this.getAttribute('data-region');
            if (selectedRegion === 'all') {
                displayedResults = [...testResults];
            } else {
                displayedResults = testResults.filter(result => result.locationCode === selectedRegion);
            }
            
            showingAll = false;
            displayFilteredResults();
        });
    });
}

function displayFilteredResults() {
    const ipList = document.getElementById('ip-list');
    const resultCount = document.getElementById('result-count');
    const showMoreSection = document.getElementById('show-more-section');
    const showMoreBtn = document.getElementById('show-more-btn');
    const ipDisplayInfo = document.getElementById('ip-display-info');
    
    if (displayedResults.length === 0) {
        ipList.innerHTML = '<div class="ip-item">未找到有效的IP</div>';
        resultCount.textContent = '';
        ipDisplayInfo.textContent = '';
        showMoreSection.style.display = 'none';
        updateButtonStates();
        return;
    }
    
    const maxDisplayCount = showingAll ? displayedResults.length : Math.min(displayedResults.length, 16);
    const currentResults = displayedResults.slice(0, maxDisplayCount);
    
    const totalCount = testResults.length;
    const filteredCount = displayedResults.length;
    
    if (filteredCount <= 16) {
        resultCount.textContent = '(共测试出 ' + totalCount + ' 个有效IP，筛选出 ' + filteredCount + ' 个)';
        ipDisplayInfo.textContent = '显示全部 ' + filteredCount + ' 个筛选结果';
        showMoreSection.style.display = 'none';
    } else {
        resultCount.textContent = '(共测试出 ' + totalCount + ' 个有效IP，筛选出 ' + filteredCount + ' 个)';
        ipDisplayInfo.textContent = '显示前 ' + maxDisplayCount + ' 个筛选结果，共 ' + filteredCount + ' 个';
        showMoreSection.style.display = 'block';
        showMoreBtn.textContent = showingAll ? '显示更少' : '显示更多';
        showMoreBtn.disabled = false;
    }
    
    const resultsHTML = currentResults.map(result => {
        const calibratedLatency = result.calibratedLatency || calibrateLatency(result.latency);
        
        let latencyClass = 'good-latency';
        if (calibratedLatency > 200) latencyClass = 'bad-latency';
        else if (calibratedLatency > 100) latencyClass = 'medium-latency';
        
        let speedClass = 'good-speed';
        let speedText = '速度:N/A';
        if (result.speed !== null) {
            if (result.speed < 5) speedClass = 'bad-speed';
            else if (result.speed < 10) speedClass = 'medium-speed';
            speedText = \`速度:\${result.speed.toFixed(2)}Mbps\`;
        }
        
        return \`<div class="ip-item"><span class="\${latencyClass}">\${result.display.split(' 延迟:')[0]} 延迟:\${calibratedLatency}ms</span> <span class="\${speedClass}">\${speedText}</span></div>\`;
    }).join('');
    
    ipList.innerHTML = resultsHTML;
    updateButtonStates();
}

async function loadIPs(ipSource, port, count) {
    try {
        const response = await fetch(\`?loadIPs=\${ipSource}&port=\${port}&count=\${count}\`, {
            method: 'GET'
        });
        
        if (!response.ok) {
            throw new Error('Failed to load IPs');
        }
        
        const data = await response.json();
        return data.ips || [];
    } catch (error) {
        return [];
    }
}

async function startTest() {
    const testBtn = document.getElementById('test-btn');
    const portSelect = document.getElementById('port-select');
    const ipSourceSelect = document.getElementById('ip-source-select');
    const countInput = document.getElementById('count-input');
    const concurrencyInput = document.getElementById('concurrency-input');
    const customTestUrl = document.getElementById('custom-test-url');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const ipList = document.getElementById('ip-list');
    const resultCount = document.getElementById('result-count');
    const ipCount = document.getElementById('ip-count');
    const ipDisplayInfo = document.getElementById('ip-display-info');
    const showMoreSection = document.getElementById('show-more-section');
    
    const selectedPort = portSelect.value;
    const selectedIPSource = ipSourceSelect.value;
    const selectedCount = parseInt(countInput.value) || 50;
    const selectedConcurrency = parseInt(concurrencyInput.value) || 6;
    const customUrl = customTestUrl.value || null;
    
    localStorage.setItem(StorageKeys.PORT, selectedPort);
    localStorage.setItem(StorageKeys.IP_SOURCE, selectedIPSource);
    localStorage.setItem(StorageKeys.COUNT, selectedCount);
    localStorage.setItem(StorageKeys.CONCURRENCY, selectedConcurrency);
    if (customUrl) {
        localStorage.setItem(StorageKeys.TEST_URL, customUrl);
    }
    
    testBtn.disabled = true;
    testBtn.textContent = '加载IP列表...';
    portSelect.disabled = true;
    ipSourceSelect.disabled = true;
    countInput.disabled = true;
    concurrencyInput.disabled = true;
    customTestUrl.disabled = true;
    testResults = [];
    displayedResults = [];
    showingAll = false;
    currentDisplayType = 'loading';
    ipList.innerHTML = '<div class="ip-item">正在加载IP列表，请稍候...</div>';
    ipDisplayInfo.textContent = '';
    showMoreSection.style.display = 'none';
    updateButtonStates();
    
    progressBar.style.width = '0%';
    
    let ipSourceName = '';
    switch(selectedIPSource) {
        case 'official':
            ipSourceName = 'CF官方';
            break;
        case 'as13335':
            ipSourceName = 'AS13335';
            break;
        case 'as209242':
            ipSourceName = 'AS209242';
            break;
        case 'as24429':
            ipSourceName = 'Alibaba';
            break;
        case 'as199524':
            ipSourceName = 'G-Core';
            break;
        case 'local':
            ipSourceName = '本地上传';
            break;
        default:
            ipSourceName = '未知';
    }
    
    progressText.textContent = '正在加载 ' + ipSourceName + ' IP列表...';
    
    if (selectedIPSource === 'local') {
        const savedFilesSelect = document.getElementById('saved-files-select');
        const fileId = savedFilesSelect.value;

        if (!fileId) {
            if (originalIPs.length === 0) {
                showMessage('请先上传IP列表文件或选择已保存的文件', 'error');
                testBtn.disabled = false;
                testBtn.textContent = '开始测试延迟和速度';
                portSelect.disabled = false;
                ipSourceSelect.disabled = false;
                countInput.disabled = false;
                concurrencyInput.disabled = false;
                progressText.textContent = '未加载IP列表';
                return;
            }
            
            const allIPs = [...originalIPs];
            const shuffled = shuffleArray(allIPs);
            originalIPs = selectedCount < shuffled.length ? 
                shuffled.slice(0, selectedCount) : shuffled;
        } else {
            const fileData = localStorage.getItem(LocalStorageKeys.FILE_PREFIX + fileId);
            if (!fileData) {
                showMessage('文件不存在，请重新上传', 'error');
                testBtn.disabled = false;
                testBtn.textContent = '开始测试延迟和速度';
                portSelect.disabled = false;
                ipSourceSelect.disabled = false;
                countInput.disabled = false;
                concurrencyInput.disabled = false;
                progressText.textContent = '文件不存在';
                return;
            }

            const parsedData = JSON.parse(fileData);
            const currentPort = selectedPort;
            const parsedIPs = parseFileContent(parsedData.content, currentPort);

            if (parsedIPs.length === 0) {
                showMessage('文件中没有有效的IP地址', 'error');
                testBtn.disabled = false;
                testBtn.textContent = '开始测试延迟和速度';
                portSelect.disabled = false;
                ipSourceSelect.disabled = false;
                countInput.disabled = false;
                concurrencyInput.disabled = false;
                progressText.textContent = '无有效IP';
                return;
            }

            const shuffled = shuffleArray(parsedIPs);
            originalIPs = selectedCount < shuffled.length ? 
                shuffled.slice(0, selectedCount) : shuffled;
            
            showMessage(\`从文件中随机选择 \${originalIPs.length} 个IP进行测试\`, 'info');
        }
    } else {
        originalIPs = await loadIPs(selectedIPSource, selectedPort, selectedCount);
    }

    if (originalIPs.length === 0) {
        ipList.innerHTML = '<div class="ip-item">加载IP列表失败，请重试</div>';
        ipCount.textContent = '0 个';
        testBtn.disabled = false;
        testBtn.textContent = '开始测试延迟和速度';
        portSelect.disabled = false;
        ipSourceSelect.disabled = false;
        countInput.disabled = false;
        concurrencyInput.disabled = false;
        progressText.textContent = '加载失败';
        return;
    }
    
    ipCount.textContent = originalIPs.length + ' 个';
    
    displayLoadedIPs();
    
    testBtn.textContent = '测试中...';
    progressText.textContent = '开始测试端口 ' + selectedPort + '...';
    currentDisplayType = 'testing';

    showMoreSection.style.display = 'none';
    
    const results = await testIPsWithConcurrency(originalIPs, selectedPort, selectedConcurrency, customUrl);
    
    testResults = results.sort((a, b) => {
        if (a.latency !== b.latency) {
            return a.latency - b.latency;
        }
        return (b.speed || 0) - (a.speed || 0);
    });
    
    currentDisplayType = 'results';
    showingAll = false;
    displayResults();
    
    createRegionFilter();
    
    testBtn.disabled = false;
    testBtn.textContent = '重新测试';
    portSelect.disabled = false;
    ipSourceSelect.disabled = false;
    countInput.disabled = false;
    concurrencyInput.disabled = false;
    customTestUrl.disabled = false;
    progressText.textContent = '完成 - 有效IP: ' + testResults.length + '/' + originalIPs.length + ' (端口: ' + selectedPort + ', IP库: ' + ipSourceName + ')';
}
</script>
</body>
</html>`;

    const response = new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
        },
    });
    
    if (sessionResult.refreshed) {
        response.headers.set('Set-Cookie', setSessionCookie(sessionId));
    }
    
    return response;
}