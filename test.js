const axios = require('axios');

// إعدادات Mailcow API
const MAILCOW_API_URL = 'https://mail.bltnm.store/api/v1/get/domain/all';
const API_KEY = '830156-55DDCF-1E211F-DBC5E6-9F7135';  // استبدل بالمفتاح الخاص بك

// دالة لعمل طلب مع retry
async function fetchWithRetry(url, apiKey, retries = 3, delay = 2000) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await axios.get(url, {
                headers: {
                    'X-API-Key': apiKey
                },
                timeout: 60000 // 60 ثانية
            });
            return response.data;
        } catch (err) {
            console.log(`Attempt ${i + 1} failed: ${err.message}`);
            if (i < retries - 1) {
                await new Promise(res => setTimeout(res, delay)); // تأخير قبل إعادة المحاولة
            } else {
                throw err;
            }
        }
    }
}

(async () => {
    try {
        const data = await fetchWithRetry(MAILCOW_API_URL, API_KEY, 5, 3000);
        console.log('Domains:', data);
    } catch (err) {
        console.error('Failed to fetch domains:', err.message);
    }
})();
