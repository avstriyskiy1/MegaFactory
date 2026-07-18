/**
 * Cloudflare Worker — приём счёта из игры и отправка его в глобальный
 * рейтинг VK (secure.addAppEvent).
 *
 * Нужные секреты (задаются командой `wrangler secret put ...`, см. README):
 *   VK_APP_ID          — ID приложения (число)
 *   VK_SECRET_KEY       — "Защищённый ключ" из настроек приложения
 *                          (используется ТОЛЬКО для проверки подписи sign)
 *   VK_SERVICE_TOKEN    — "Сервисный ключ доступа" из настроек приложения
 *                          (используется для вызова secure.addAppEvent)
 *   VK_ACTIVITY_ID      — ID активности рейтинга, настроенной в разделе
 *                          "Рейтинг" в настройках приложения (число, обычно 1)
 */

const VK_API_VERSION = '5.199';

export default {
  async fetch(request, env) {
    // CORS: разрешаем запросы из мини-приложения (запускается во фрейме vk.com)
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

    const { launchParams, value } = body || {};
    if (!launchParams || typeof launchParams !== 'string') {
      return json({ error: 'missing_launch_params' }, 400, corsHeaders);
    }
    if (!Number.isFinite(value) || value < 0) {
      return json({ error: 'invalid_value' }, 400, corsHeaders);
    }

    // ── 1. Проверяем подпись параметров запуска ──────────────────
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

    // ── 2. Отправляем очки в VK ────────────────────────────────────
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
  },
};

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

// launchParams приходит как строка вида "vk_user_id=1&vk_app_id=2&sign=..."
// (без ведущего "?" — так и присылаем с клиента)
function parseParams(launchParams) {
  return new URLSearchParams(launchParams);
}

// Официальный алгоритм проверки подписи VK Mini Apps:
// берём все vk_* параметры, сортируем по ключу, склеиваем в query-строку,
// считаем HMAC-SHA256 с "Защищённым ключом" приложения, кодируем в base64url
// без паддинга и сравниваем со значением sign.
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
