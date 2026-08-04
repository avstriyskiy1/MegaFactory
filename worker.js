/**
 * Cloudflare Worker — общий backend игры:
 *  1) приём счёта и отправка его в глобальный рейтинг VK (secure.addAppEvent)
 *  2) честный учёт приглашений друзей (засчитывается только когда
 *     приглашённый реально открыл игру и нажал "Начать" на своём устройстве)
 *  3) промокоды — активация игроками + управление админом (создание,
 *     удаление, лимиты активаций, срок действия, "блогерские" коды)
 *  4) настоящие покупки через VK Pay (VKWebAppShowOrderBox) — приём
 *     платёжных уведомлений VK и выдача награды только после реальной оплаты
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
 *   VK_PAYMENTS_SECRET  — "Секретный ключ" именно из раздела "Платежи"
 *                          настроек приложения (это ДРУГОЙ ключ, не
 *                          VK_SECRET_KEY! См. PAYMENTS-SETUP.md).
 *
 * Нужен KV-namespace, привязанный в wrangler.toml под именем REFERRALS
 * (см. README — команда `wrangler kv namespace create REFERRALS`).
 * Промокоды и покупки хранятся в том же KV, отдельными префиксами ключей —
 * заводить второй namespace не требуется.
 */

const VK_API_VERSION = '5.199';
const PROMO_REWARD_TYPES = ['coins', 'crystals', 'starterPack', 'vipStatus', 'secretLab'];

// ── Каталог платных предметов ────────────────────────────────────
// ВАЖНО: price указан в внутренней валюте VK ("голоса"), а не в рублях!
// Это ПРИМЕРНЫЕ значения — проверь актуальный курс голосов к рублю в своём
// личном кабинете разработчика (раздел "Платежи") и поправь под реальные
// 99₽/299₽/199₽/59₽ ПЕРЕД тем как включать боевой режим платежей.
// permanent:true — разовая покупка (флаг на аккаунте), false — можно купить
// несколько раз (например пачку монет).
const PAYMENT_CATALOG = {
  starter_pack: { title: 'Стартовый набор',      price: 40,  permanent: true  },
  vip_status:   { title: 'VIP-статус',            price: 120, permanent: true  },
  secret_lab:   { title: 'Секретная лаборатория', price: 80,  permanent: true  },
  coin_pack:    { title: 'Мешок монет',           price: 25,  permanent: false },
  auto_pilot:   { title: 'Автопилот завода',      price: 60,  permanent: true  },
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ── Платёжные уведомления VK — ОТДЕЛЬНЫЙ протокол ──────────────
    // VK шлёт form-urlencoded (не JSON!) и подписывает по своей MD5-схеме
    // (не той HMAC-схеме, что у launchParams) — обрабатываем до общего
    // JSON-парсинга ниже, иначе оно упадёт на попытке request.json().
    if (url.pathname === '/vk-payments-callback') {
      return handlePaymentNotification(request, env);
    }

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
    // Отмечаем "последний раз видели" — используется ночной задачей-напоминалкой
    // ниже (scheduled), чтобы не слать уведомление тем, кто и так активен.
    ctx?.waitUntil?.(env.REFERRALS.put(`last_seen:${userId}`, String(Date.now())));

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
      case '/save-game':
        return handleSaveGame(body, userId, env, corsHeaders);
      case '/load-game':
        return handleLoadGame(userId, env, corsHeaders);
      case '/my-purchases':
        return handleMyPurchases(userId, env, corsHeaders);
      case '/friends-scores':
        return handleFriendsScores(body, userId, env, corsHeaders);
      case '/register-notifications':
        return handleRegisterNotifications(body, userId, env, corsHeaders);
      default:
        return json({ error: 'not_found' }, 404, corsHeaders);
    }
  },

  // ── Ночная задача-напоминалка (Cron Trigger, см. wrangler.toml) ──
  // Раз в час: находим тех, кто разрешил уведомления, давно не заходил и
  // кому мы не писали в последние сутки — шлём одно короткое напоминание.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sendInactivityReminders(env));
  },
};

const INACTIVITY_THRESHOLD_MS = 20 * 60 * 60 * 1000; // 20 часов без захода
const REMINDER_COOLDOWN_MS    = 24 * 60 * 60 * 1000; // не чаще раза в сутки
const REMINDER_MESSAGE = 'Твой завод скучает без тебя! Загляни забрать накопившийся офлайн-доход 🏭';

async function sendInactivityReminders(env) {
  if (!env.VK_SERVICE_TOKEN) return;
  const list = await env.REFERRALS.list({ prefix: 'notif_allowed:' });
  const now = Date.now();
  const toNotify = [];

  for (const key of list.keys) {
    const userId = key.name.slice('notif_allowed:'.length);
    const lastSeenRaw = await env.REFERRALS.get(`last_seen:${userId}`);
    const lastSeen = lastSeenRaw ? Number(lastSeenRaw) : 0;
    if (now - lastSeen < INACTIVITY_THRESHOLD_MS) continue; // ещё активен

    const lastSentRaw = await env.REFERRALS.get(`notif_sent:${userId}`);
    const lastSent = lastSentRaw ? Number(lastSentRaw) : 0;
    if (now - lastSent < REMINDER_COOLDOWN_MS) continue; // уже писали недавно

    toNotify.push(userId);
  }
  if (!toNotify.length) return;

  // VK принимает до 100 user_ids за один вызов notifications.sendMessage
  for (let i = 0; i < toNotify.length; i += 100) {
    const batch = toNotify.slice(i, i + 100);
    try {
      const apiUrl = new URL('https://api.vk.com/method/notifications.sendMessage');
      apiUrl.searchParams.set('user_ids', batch.join(','));
      apiUrl.searchParams.set('message', REMINDER_MESSAGE);
      apiUrl.searchParams.set('access_token', env.VK_SERVICE_TOKEN);
      apiUrl.searchParams.set('v', VK_API_VERSION);
      const res = await fetch(apiUrl.toString(), { method: 'POST' });
      const data = await res.json();
      // Отмечаем отправку только тем, кому реально ушло (VK возвращает
      // response:[{user_id, status}] — status:1 значит успех)
      const sentIds = new Set(
        (data.response || [])
          .filter(r => r.status === 1)
          .map(r => String(r.user_id))
      );
      await Promise.all(
        batch
          .filter(id => sentIds.has(String(id)))
          .map(id => env.REFERRALS.put(`notif_sent:${id}`, String(now)))
      );
    } catch (e) {
      console.error('[notifications.sendMessage error]', e.message);
    }
  }
}

// ── /submit-score ────────────────────────────────────────────────
async function handleSubmitScore(body, userId, env, corsHeaders) {
  const { value, rawCoins } = body;
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
  // Отдельно — настоящее (несжатое) число монет, только для показа в списке
  // друзей внутри игры. К рейтингу VK отношения не имеет.
  if (Number.isFinite(rawCoins) && rawCoins >= 0) {
    await env.REFERRALS.put(`score_raw:${userId}`, String(Math.floor(rawCoins)));
  }
  return json({ ok: true }, 200, corsHeaders);
}

// ── /friends-scores ──────────────────────────────────────────────
// Игра сама узнаёт список друзей через VKWebAppGetFriends (имена/аватарки
// не нужно хранить у нас), а тут только спрашивает счёт каждого из них,
// если они тоже играли и хоть раз отправляли счёт.
async function handleFriendsScores(body, userId, env, corsHeaders) {
  const { friendIds } = body;
  if (!Array.isArray(friendIds) || friendIds.length === 0) {
    return json({ error: 'invalid_friend_ids' }, 400, corsHeaders);
  }
  const ids = friendIds.map(String).slice(0, 100);
  const scores = {};
  await Promise.all(ids.map(async id => {
    const raw = await env.REFERRALS.get(`score_raw:${id}`);
    if (raw != null) scores[id] = Number(raw);
  }));
  const ownRaw = await env.REFERRALS.get(`score_raw:${userId}`);
  return json({ ok: true, scores, own: ownRaw != null ? Number(ownRaw) : 0 }, 200, corsHeaders);
}

// ── /register-notifications ─────────────────────────────────────
// Игрок разрешил уведомления через VKWebAppAllowNotifications на клиенте —
// запоминаем это здесь, чтобы ночная задача (см. scheduled ниже) знала кому
// можно писать. allowed:false — отзыв согласия (тоже стираем отметку).
async function handleRegisterNotifications(body, userId, env, corsHeaders) {
  const allowed = !!body.allowed;
  if (allowed) {
    await env.REFERRALS.put(`notif_allowed:${userId}`, '1');
  } else {
    await env.REFERRALS.delete(`notif_allowed:${userId}`);
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

// ── /save-game ───────────────────────────────────────────────────
// Настоящее облачное сохранение (VKWebAppStorageSet для этого не годится —
// у него лимит 4096 байт, а сохранение игры весит намного больше).
async function handleSaveGame(body, userId, env, corsHeaders) {
  const { data } = body;
  if (!data || typeof data !== 'string' || data.length > 900000) {
    return json({ error: 'invalid_data' }, 400, corsHeaders);
  }
  await env.REFERRALS.put(`save:${userId}`, data);
  return json({ ok: true }, 200, corsHeaders);
}

// ── /load-game ───────────────────────────────────────────────────
async function handleLoadGame(userId, env, corsHeaders) {
  const save = await env.REFERRALS.get(`save:${userId}`);
  return json({ ok: true, save: save || null }, 200, corsHeaders);
}

// ── /vk-payments-callback ────────────────────────────────────────
// Единая точка входа для платёжных уведомлений VK (see PAYMENTS-SETUP.md).
// Награда выдаётся ТОЛЬКО отсюда, после реального прохождения оплаты —
// клиент никогда не может сам себе её начислить.
async function handlePaymentNotification(request, env) {
  const text = await request.text();
  const params = new URLSearchParams(text);

  const sig = params.get('sig');
  const expectedSig = await vkPaymentsSign(params, env.VK_PAYMENTS_SECRET || '');
  if (!sig || !env.VK_PAYMENTS_SECRET || sig !== expectedSig) {
    return paymentsJson({ error: { error_code: 10, error_msg: 'Bad signature', critical: true } });
  }

  const notifType = (params.get('notification_type') || '').replace(/_test$/, '');
  const userId = params.get('user_id');
  const item = params.get('item');
  const cat = item ? PAYMENT_CATALOG[item] : null;

  if (notifType === 'get_item') {
    if (!cat) {
      return paymentsJson({ error: { error_code: 20, error_msg: 'Product does not exist', critical: true } });
    }
    return paymentsJson({ response: { title: cat.title, price: cat.price } });
  }

  if (notifType === 'order_status_change') {
    if (!cat) {
      return paymentsJson({ error: { error_code: 20, error_msg: 'Product does not exist', critical: true } });
    }
    const status = params.get('status');
    const orderId = params.get('order_id');

    if (status === 'chargeable') {
      // Идемпотентность: если это уведомление повторное (тот же order_id),
      // нужно вернуть ТОТ ЖЕ ответ, а не выдавать награду повторно.
      const idemKey = `processed_order:${orderId}`;
      const already = await env.REFERRALS.get(idemKey);
      if (already) {
        return paymentsJson({ response: { order_id: Number(orderId), app_order_id: Number(already) } });
      }
      const appOrderId = Date.now();
      if (cat.permanent) {
        await env.REFERRALS.put(`purchase:${userId}:${item}`, '1');
      } else {
        const pendingKey = `pending:${userId}`;
        const raw = await env.REFERRALS.get(pendingKey);
        const list = raw ? JSON.parse(raw) : [];
        list.push({ item, orderId, at: Date.now() });
        await env.REFERRALS.put(pendingKey, JSON.stringify(list));
      }
      await env.REFERRALS.put(idemKey, String(appOrderId));
      return paymentsJson({ response: { order_id: Number(orderId), app_order_id: appOrderId } });
    }

    if (status === 'refunded') {
      if (cat.permanent) {
        await env.REFERRALS.delete(`purchase:${userId}:${item}`);
      }
      return paymentsJson({ response: { order_id: Number(orderId), app_order_id: Date.now() } });
    }

    return paymentsJson({ response: {} });
  }

  return paymentsJson({ error: { error_code: 1, error_msg: notifType + ' not processed', critical: true } });
}

function paymentsJson(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

// Подпись VK Payments: md5(конкатенация "ключ=значение" по всем параметрам
// кроме sig, отсортированным по алфавиту, + секрет из раздела "Платежи").
// Это ДРУГАЯ, более старая схема, чем HMAC-подпись launchParams в
// остальной части воркера — VK всё ещё использует именно её для платежей.
async function vkPaymentsSign(params, secret) {
  const pairs = [];
  for (const [k, v] of params.entries()) {
    if (k === 'sig') continue;
    pairs.push([k, v]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const concat = pairs.map(([k, v]) => `${k}=${v}`).join('') + secret;
  return md5Hex(concat);
}

// ── /my-purchases ────────────────────────────────────────────────
// Игра спрашивает отсюда, что реально куплено (после успешной оплаты воркер
// уже записал это через handlePaymentNotification выше). pending — разовые
// награды-расходники (например пачка монет), выдаются один раз и стираются.
async function handleMyPurchases(userId, env, corsHeaders) {
  const purchases = {};
  for (const item of Object.keys(PAYMENT_CATALOG)) {
    if (!PAYMENT_CATALOG[item].permanent) continue;
    const owned = await env.REFERRALS.get(`purchase:${userId}:${item}`);
    if (owned) purchases[item] = true;
  }
  const pendingKey = `pending:${userId}`;
  const raw = await env.REFERRALS.get(pendingKey);
  const pending = raw ? JSON.parse(raw) : [];
  if (pending.length) await env.REFERRALS.delete(pendingKey);
  return json({ ok: true, purchases, pending }, 200, corsHeaders);
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

// ── MD5 (RFC 1321) ───────────────────────────────────────────────
// Web Crypto API (crypto.subtle) сознательно не поддерживает MD5 — он
// считается небезопасным для новых применений. Но VK Payments всё ещё
// подписывает уведомления именно MD5 (это их легаси-протокол), так что
// без собственной реализации тут не обойтись. Используется ТОЛЬКО для
// проверки подписи платёжных уведомлений, ни для чего больше.
function md5Hex(str) {
  const K = [
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
  ];
  const S = [
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
  ];

  const msg = new TextEncoder().encode(str);
  const totalLen = (((msg.length + 8) >> 6) << 6) + 64;
  const buf = new Uint8Array(totalLen);
  buf.set(msg);
  buf[msg.length] = 0x80;
  const dv = new DataView(buf.buffer);
  const bitLen = msg.length * 8;
  dv.setUint32(totalLen - 8, bitLen >>> 0, true);
  dv.setUint32(totalLen - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const rotl = (n, c) => (n << c) | (n >>> (32 - c));

  for (let off = 0; off < totalLen; off += 64) {
    const M = new Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16)      { F = (B & C) | (~B & D);      g = i; }
      else if (i < 32) { F = (D & B) | (~D & C);      g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D;                g = (3 * i + 5) % 16; }
      else              { F = C ^ (B | (~D >>> 0));    g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }

  const toLE = n => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  };
  return toLE(a0) + toLE(b0) + toLE(c0) + toLE(d0);
}
