/**
 * Cloudflare Worker — общий backend игры:
 *  1) приём счёта и отправка его в глобальный рейтинг VK (secure.addAppEvent)
 *  2) честный учёт приглашений друзей (засчитывается только когда
 *     приглашённый реально открыл игру и нажал "Начать" на своём устройстве)
 *  3) промокоды — активация игроками + управление админом (создание,
 *     удаление, лимиты активаций, срок действия, "блогерские" коды)
 *
 * Нужные секреты (задаются командой `wrangler secret put ...`, см. README):
 *   VK_APP_ID          — ID приложения (число)
 *   VK_SECRET_KEY       — "Защищённый ключ" из настроек приложения
 *                          (используется ТОЛЬКО для проверки подписи sign)
 *   VK_SERVICE_TOKEN    — "Сервисный ключ доступа" из настроек приложения
 *                          (используется для вызова secure.addAppEvent)
 *   VK_ACTIVITY_ID      — ID активности рейтинга, настроенной в разделе
 *                          "Рейтинг" в настройках приложения (число, обычно 1)
 *   ADMIN_KEY           — придуманный тобой пароль для панели администратора
 *                          промокодов (см. admin.html). Придумай длинную
 *                          случайную строку, никому её не показывай.
 *
 * Нужен KV-namespace, привязанный в wrangler.toml под именем REFERRALS
 * (см. README — команда `wrangler kv namespace create REFERRALS`).
 * Промокоды хранятся в том же KV, отдельным префиксом ключей — заводить
 * второй namespace не требуется.
 */

const VK_API_VERSION = '5.199';
const PROMO_REWARD_TYPES = ['coins', 'crystals', 'starterPack', 'vipStatus', 'secretLab'];

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    if (request.method !== 'POST') {
      return json({ error: 'method_not_allowed' }, 405, corsHeaders);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'invalid_json' }, 400, corsHeaders);
    }

    const url = new URL(request.url);

    // ── Админ-маршруты — своя авторизация по ключу, VK тут ни при чём ──
    if (url.pathname.startsWith('/admin/')) {
      if (!env.ADMIN_KEY || !body.adminKey || body.adminKey !== env.ADMIN_KEY) {
        return json({ error: 'unauthorized' }, 401, corsHeaders);
      }
      switch (url.pathname) {
        case '/admin/codes/list':   return handleAdminListCodes(env, corsHeaders);
        case '/admin/codes/create': return handleAdminCreateCode(body, env, corsHeaders);
        case '/admin/codes/update': return handleAdminUpdateCode(body, env, corsHeaders);
        case '/admin/codes/delete': return handleAdminDeleteCode(body, env, corsHeaders);
        default: return json({ error: 'not_found' }, 404, corsHeaders);
      }
    }

    // ── Остальные маршруты — требуют валидных launchParams (подпись VK) ──
    const { launchParams } = body || {};
    if (!launchParams || typeof launchParams !== 'string') {
      return json({ error: 'missing_launch_params' }, 400, corsHeaders);
    }
    const params = parseParams(launchParams);
    const isValid = await verifySign(params, env.VK_SECRET_KEY);
    if (!isValid) {
      return json({ error: 'invalid_sign' }, 403, corsHeaders);
    }
    const appId = params.get('vk_app_id');
    const userId = params.get('vk_user_id');
    if (String(appId) !== String(env.VK_APP_ID) || !userId) {
      return json({ error: 'app_or_user_mismatch' }, 403, corsHeaders);
    }

    switch (url.pathname) {
      case '/submit-score':
        return handleSubmitScore(body, userId, env, corsHeaders);
      case '/register-ref':
        return handleRegisterRef(body, userId, env, corsHeaders);
      case '/confirm-ref':
        return handleConfirmRef(body, userId, env, corsHeaders);
      case '/my-invited':
        return handleMyInvited(userId, env, corsHeaders);
      case '/redeem-code':
        return handleRedeemCode(body, userId, env, corsHeaders);
      default:
        return json({ error: 'not_found' }, 404, corsHeaders);
    }
  },
};

// ── /submit-score ────────────────────────────────────────────────
async function handleSubmitScore(body, userId, env, corsHeaders) {
  const { value } = body;
  if (!Number.isFinite(value) || value < 0) {
    return json({ error: 'invalid_value' }, 400, corsHeaders);
  }

  const apiUrl = new URL('https://api.vk.com/method/secure.addAppEvent');
  apiUrl.searchParams.set('user_id', userId);
  apiUrl.searchParams.set('activity_id', env.VK_ACTIVITY_ID);
  apiUrl.searchParams.set('value', String(Math.floor(value)));
  apiUrl.searchParams.set('access_token', env.VK_SERVICE_TOKEN);
  apiUrl.searchParams.set('v', VK_API_VERSION);

  const vkRes = await fetch(apiUrl.toString(), { method: 'POST' });
  const vkData = await vkRes.json();
  if (vkData.error) {
    console.error('[VK secure.addAppEvent error]', JSON.stringify(vkData.error));
    return json({ error: 'vk_api_error', details: vkData.error }, 502, corsHeaders);
  }
  return json({ ok: true }, 200, corsHeaders);
}

// ── /register-ref ───────────────────────────────────────────────
async function handleRegisterRef(body, userId, env, corsHeaders) {
  const { code } = body;
  if (!code || typeof code !== 'string' || code.length > 32) {
    return json({ error: 'invalid_code' }, 400, corsHeaders);
  }
  const key = `refcode:${code}`;
  const existing = await env.REFERRALS.get(key);
  if (!existing) {
    await env.REFERRALS.put(key, userId);
  }
  return json({ ok: true }, 200, corsHeaders);
}

// ── /confirm-ref ─────────────────────────────────────────────────
async function handleConfirmRef(body, userId, env, corsHeaders) {
  const { code } = body;
  if (!code || typeof code !== 'string') {
    return json({ error: 'invalid_code' }, 400, corsHeaders);
  }

  const ownerId = await env.REFERRALS.get(`refcode:${code}`);
  if (!ownerId) {
    return json({ error: 'unknown_code' }, 404, corsHeaders);
  }
  if (String(ownerId) === String(userId)) {
    return json({ error: 'self_referral' }, 400, corsHeaders);
  }

  const referredKey = `referred:${userId}`;
  const already = await env.REFERRALS.get(referredKey);
  if (already) {
    return json({ ok: true, alreadyCounted: true }, 200, corsHeaders);
  }

  await env.REFERRALS.put(referredKey, code);

  const countKey = `invited_count:${ownerId}`;
  const current = parseInt((await env.REFERRALS.get(countKey)) || '0', 10);
  await env.REFERRALS.put(countKey, String(current + 1));

  return json({ ok: true, alreadyCounted: false }, 200, corsHeaders);
}

// ── /my-invited ──────────────────────────────────────────────────
async function handleMyInvited(userId, env, corsHeaders) {
  const count = parseInt((await env.REFERRALS.get(`invited_count:${userId}`)) || '0', 10);
  return json({ ok: true, invited: count }, 200, corsHeaders);
}

// ── /redeem-code ─────────────────────────────────────────────────
// Активация промокода игроком. Награда не начисляется тут напрямую (игра
// хранит прогресс на устройстве игрока) — воркер только проверяет право на
// активацию и возвращает описание награды, которое клиент применяет сам.
async function handleRedeemCode(body, userId, env, corsHeaders) {
  const { code } = body;
  if (!code || typeof code !== 'string') {
    return json({ error: 'invalid_code' }, 400, corsHeaders);
  }
  const normCode = code.trim().toUpperCase();
  const key = `promo:${normCode}`;
  const raw = await env.REFERRALS.get(key);
  if (!raw) return json({ error: 'not_found' }, 404, corsHeaders);

  const entry = JSON.parse(raw);
  if (!entry.active) return json({ error: 'inactive' }, 400, corsHeaders);
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    return json({ error: 'expired' }, 400, corsHeaders);
  }
  if (entry.maxActivations != null && entry.usedCount >= entry.maxActivations) {
    return json({ error: 'exhausted' }, 400, corsHeaders);
  }

  const usedKey = `promoused:${normCode}:${userId}`;
  const alreadyUsedThis = await env.REFERRALS.get(usedKey);
  if (alreadyUsedThis) return json({ error: 'already_used' }, 400, corsHeaders);

  // Блогерский промокод — у одного игрока может быть активирован только
  // ОДИН такой код за всё время, независимо от того, какой именно.
  if (entry.youtuber) {
    const youtuberUsedKey = `promoyoutuberused:${userId}`;
    const alreadyYoutuber = await env.REFERRALS.get(youtuberUsedKey);
    if (alreadyYoutuber) return json({ error: 'already_used_youtuber' }, 400, corsHeaders);
    await env.REFERRALS.put(youtuberUsedKey, normCode);
  }

  await env.REFERRALS.put(usedKey, '1');
  entry.usedCount = (entry.usedCount || 0) + 1;
  await env.REFERRALS.put(key, JSON.stringify(entry));

  return json({ ok: true, reward: { type: entry.rewardType, value: entry.rewardValue } }, 200, corsHeaders);
}

// ── /admin/codes/list ────────────────────────────────────────────
async function handleAdminListCodes(env, corsHeaders) {
  const list = await env.REFERRALS.list({ prefix: 'promo:' });
  const codes = [];
  for (const k of list.keys) {
    const raw = await env.REFERRALS.get(k.name);
    if (raw) {
      try { codes.push(JSON.parse(raw)); } catch {}
    }
  }
  codes.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return json({ ok: true, codes }, 200, corsHeaders);
}

// ── /admin/codes/create ──────────────────────────────────────────
async function handleAdminCreateCode(body, env, corsHeaders) {
  const { code, rewardType, rewardValue, maxActivations, expiresAt, youtuber } = body;
  if (!code || typeof code !== 'string') return json({ error: 'invalid_code' }, 400, corsHeaders);
  const normCode = code.trim().toUpperCase();
  if (!normCode || normCode.length > 32) return json({ error: 'invalid_code' }, 400, corsHeaders);
  if (!PROMO_REWARD_TYPES.includes(rewardType)) {
    return json({ error: 'invalid_reward_type' }, 400, corsHeaders);
  }

  const key = `promo:${normCode}`;
  const existing = await env.REFERRALS.get(key);
  if (existing) return json({ error: 'code_exists' }, 409, corsHeaders);

  const entry = {
    code: normCode,
    rewardType,
    rewardValue: Number(rewardValue) || 0,
    maxActivations: (maxActivations !== null && maxActivations !== undefined && maxActivations !== '')
      ? Math.max(1, parseInt(maxActivations, 10)) : null,
    usedCount: 0,
    expiresAt: expiresAt ? Number(expiresAt) : null,
    youtuber: !!youtuber,
    active: true,
    createdAt: Date.now(),
  };
  await env.REFERRALS.put(key, JSON.stringify(entry));
  return json({ ok: true, code: entry }, 200, corsHeaders);
}

// ── /admin/codes/update ──────────────────────────────────────────
async function handleAdminUpdateCode(body, env, corsHeaders) {
  const { code, ...fields } = body;
  if (!code) return json({ error: 'invalid_code' }, 400, corsHeaders);
  const key = `promo:${String(code).trim().toUpperCase()}`;
  const raw = await env.REFERRALS.get(key);
  if (!raw) return json({ error: 'not_found' }, 404, corsHeaders);

  const entry = JSON.parse(raw);
  if (fields.rewardType !== undefined && PROMO_REWARD_TYPES.includes(fields.rewardType)) {
    entry.rewardType = fields.rewardType;
  }
  if (fields.rewardValue !== undefined) entry.rewardValue = Number(fields.rewardValue) || 0;
  if (fields.maxActivations !== undefined) {
    entry.maxActivations = (fields.maxActivations === null || fields.maxActivations === '')
      ? null : Math.max(1, parseInt(fields.maxActivations, 10));
  }
  if (fields.expiresAt !== undefined) {
    entry.expiresAt = fields.expiresAt ? Number(fields.expiresAt) : null;
  }
  if (fields.youtuber !== undefined) entry.youtuber = !!fields.youtuber;
  if (fields.active !== undefined) entry.active = !!fields.active;

  await env.REFERRALS.put(key, JSON.stringify(entry));
  return json({ ok: true, code: entry }, 200, corsHeaders);
}

// ── /admin/codes/delete ──────────────────────────────────────────
async function handleAdminDeleteCode(body, env, corsHeaders) {
  const { code } = body;
  if (!code) return json({ error: 'invalid_code' }, 400, corsHeaders);
  const key = `promo:${String(code).trim().toUpperCase()}`;
  await env.REFERRALS.delete(key);
  return json({ ok: true }, 200, corsHeaders);
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function parseParams(launchParams) {
  return new URLSearchParams(launchParams);
}

async function verifySign(params, secretKey) {
  const sign = params.get('sign');
  if (!sign || !secretKey) return false;

  const vkParams = [...params.entries()]
    .filter(([key]) => key.startsWith('vk_'))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const queryString = vkParams.map(([k, v]) => `${k}=${v}`).join('&');

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secretKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const digest = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(queryString));

  const computed = base64UrlEncode(new Uint8Array(digest));
  return computed === sign;
}

function base64UrlEncode(bytes) {
  let binary = '';
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
