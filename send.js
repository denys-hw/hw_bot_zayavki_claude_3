const crypto = require('crypto');

// Проверяем, что запрос действительно пришёл от Telegram Web App,
// а не от постороннего, который просто угадал URL и chat_id.
// Алгоритм описан в официальной документации Telegram:
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
function validateInitData(initData, botToken) {
    if (!initData) return false;

    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    if (!hash) return false;

    urlParams.delete('hash');

    const dataCheckArr = [];
    for (const [key, value] of urlParams.entries()) {
        dataCheckArr.push(`${key}=${value}`);
    }
    dataCheckArr.sort();
    const dataCheckString = dataCheckArr.join('\n');

    const secretKey = crypto
        .createHmac('sha256', 'WebAppData')
        .update(botToken)
        .digest();

    const calculatedHash = crypto
        .createHmac('sha256', secretKey)
        .update(dataCheckString)
        .digest('hex');

    return calculatedHash === hash;
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }

    const BOT_TOKEN = process.env.BOT_TOKEN;
    if (!BOT_TOKEN) {
        res.status(500).json({ error: 'BOT_TOKEN не настроен на сервере' });
        return;
    }

    const { chat_id, text, initData } = req.body || {};

    if (!chat_id || !text) {
        res.status(400).json({ error: 'Не переданы chat_id или text' });
        return;
    }

    // Проверка подлинности запроса. Можно временно закомментировать на этапе
    // отладки, но для продакшена оставляйте включённой, иначе кто угодно
    // сможет слать сообщения через ваш backend от имени бота.
    if (!validateInitData(initData, BOT_TOKEN)) {
        res.status(403).json({ error: 'Не удалось подтвердить подлинность запроса' });
        return;
    }

    try {
        const tgResponse = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id,
                text,
                parse_mode: 'HTML'
            })
        });

        const tgData = await tgResponse.json();

        if (!tgResponse.ok) {
            res.status(502).json({ error: tgData.description || 'Ошибка Telegram API' });
            return;
        }

        res.status(200).json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
};
