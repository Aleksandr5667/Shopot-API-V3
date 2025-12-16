import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: "Слишком много попыток. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: { success: false, error: "Слишком много запросов. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    return req.path.startsWith('/api/upload') || req.path.startsWith('/api/media');
  },
});

export const emailLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 1,
  message: { success: false, error: "Подождите минуту перед повторной отправкой кода." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { success: false, error: "Слишком много поисковых запросов. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});

export const mediaLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 50,
  message: { success: false, error: "Слишком много запросов загрузки. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});
