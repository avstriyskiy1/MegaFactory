/**
 * Cloudflare Worker — общий backend игры:
 *  1) приём счёта и отправка его в глобальный рейтинг VK (secure.addAppEvent)
 *  2) честный учёт приглашений друзей (засчитывается только когда
 *     приглашённый реально открыл игру и нажал "Начать" на своём устройстве)
 *
 * Нужные секреты (задаются командой `wrangler secret put ...`, см. README):
 *   VK_APP_ID          — ID приложения (число)
 *   VK_SECRET_KEY       — "Защищённый ключ" из настроек приложения
 *                          (используется ТОЛЬКО для проверки подписи sign)
 *   VK_SERVICE_TOKEN    — "Сервисный ключ доступа" из настроек приложения
 *                          (используется для вызова secure.addAppEvent)
 *   VK_ACTIVITY_ID      — ID активности рейтинга, настроенной в разделе
 *                          "Рейтинг" в настройках приложения (число, обычно 1)
 *
 * Нужен KV-namespace, привязанный в wrangler.toml под именем REFERRALS
 * (см. README — команда `wrangler kv namespace create REFERRALS`).
 */

const VK_API_VERSION = '5.199';

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

    // Все маршруты требуют валидных launchParams — проверяем подпись один раз
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
    return json({ error: 'vk_api_error', details: vkData.error }, 502, corsHeaders);
  }
  return json({ ok: true }, 200, corsHeaders);
}

// ── /register-ref ───────────────────────────────────────────────
// Вызывается у того, кто ДЕЛИТСЯ ссылкой — просто запоминаем какой код
// принадлежит какому vk_user_id. Никакого приглашения тут ещё не засчитывается.
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
// Вызывается у ПРИГЛАШЁННОГО игрока, когда он реально нажал "Начать" по
// реферальной ссылке. Засчитываем приглашение автору кода — один раз на
// каждого приглашённого пользователя (защита от повторной накрутки).
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
    // Этот пользователь уже был кому-то засчитан раньше — второй раз не считаем
    return json({ ok: true, alreadyCounted: true }, 200, corsHeaders);
  }

  await env.REFERRALS.put(referredKey, code);

  const countKey = `invited_count:${ownerId}`;
  const current = parseInt((await env.REFERRALS.get(countKey)) || '0', 10);
  await env.REFERRALS.put(countKey, String(current + 1));

  return json({ ok: true, alreadyCounted: false }, 200, corsHeaders);
}

// ── /my-invited ──────────────────────────────────────────────────
// Отдаёт актуальное (серверное) число приглашённых для текущего игрока.
async function handleMyInvited(userId, env, corsHeaders) {
  const count = parseInt((await env.REFERRALS.get(`invited_count:${userId}`)) || '0', 10);
  return json({ ok: true, invited: count }, 200, corsHeaders);
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
