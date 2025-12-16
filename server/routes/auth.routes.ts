import { Router, Request, Response } from "express";
import { z } from "zod";
import bcrypt from "bcrypt";
import { storage } from "../storage";
import { authenticateToken, generateToken } from "../auth";
import { generateVerificationCode, sendVerificationEmail, sendPasswordResetEmail } from "../emailService";
import { insertUserSchema, loginSchema } from "@shared/schema";
import { sendSuccess, sendError } from "./utils";
import { authLimiter, emailLimiter } from "./limiters";

export const authRouter = Router();

authRouter.post("/register", async (req: Request, res: Response) => {
  try {
    const validation = insertUserSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const existingUser = await storage.getUserByEmail(validation.data.email);
    if (existingUser) {
      return sendError(res, "Email уже зарегистрирован");
    }

    const user = await storage.createUser(validation.data);
    
    const code = generateVerificationCode();
    await storage.createVerificationCode(user.email, code, "email_verification");
    const sent = await sendVerificationEmail(user.email, code);
    
    if (!sent) {
      console.error("Failed to send verification email to:", user.email);
    }

    return sendSuccess(res, { 
      user, 
      message: "Регистрация успешна. Проверьте email для подтверждения." 
    }, 201);
  } catch (error) {
    console.error("Register error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

const checkEmailSchema = z.object({
  email: z.string().email("Некорректный email"),
});

authRouter.post("/check-email", async (req: Request, res: Response) => {
  try {
    const validation = checkEmailSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const existingUser = await storage.getUserByEmail(validation.data.email);
    return sendSuccess(res, { available: !existingUser });
  } catch (error) {
    console.error("Check email error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

authRouter.post("/login", async (req: Request, res: Response) => {
  try {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { email, password } = validation.data;

    const lockStatus = await storage.isAccountLocked(email);
    if (lockStatus.locked) {
      const minutesLeft = lockStatus.lockedUntil 
        ? Math.ceil((lockStatus.lockedUntil.getTime() - Date.now()) / 60000)
        : 15;
      return sendError(res, `Слишком много попыток. Попробуйте через ${minutesLeft} минут.`, 429);
    }

    const user = await storage.getUserByEmail(email);
    if (!user) {
      return sendError(res, "Пользователь не найден", 404);
    }

    if (!user.emailVerified) {
      return sendError(res, "Email не подтверждён. Проверьте почту или запросите код повторно.", 403);
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      const result = await storage.incrementFailedLoginAttempts(email);
      const attemptsLeft = 5 - result.attempts;
      
      if (result.lockedUntil) {
        return sendError(res, "Слишком много попыток. Попробуйте через 15 минут.", 429);
      }
      
      return sendError(res, `Неверный пароль. Осталось попыток: ${attemptsLeft}`, 401);
    }

    await storage.resetFailedLoginAttempts(email);
    await storage.updateLastSeen(user.id);
    const token = generateToken({ userId: user.id, email: user.email });
    const { passwordHash, ...publicUser } = user;

    return sendSuccess(res, { user: publicUser, token });
  } catch (error) {
    console.error("Login error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

authRouter.get("/me", authenticateToken, async (req: Request, res: Response) => {
  try {
    const user = await storage.getUserById(req.user!.userId);
    if (!user) {
      return sendError(res, "Пользователь не найден", 404);
    }

    await storage.updateLastSeen(req.user!.userId);
    return sendSuccess(res, { user });
  } catch (error) {
    console.error("Get me error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

const sendVerificationSchema = z.object({
  email: z.string().email("Некорректный email"),
});

authRouter.post("/send-verification", emailLimiter, async (req: Request, res: Response) => {
  try {
    const validation = sendVerificationSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { email } = validation.data;

    const lastCodeTime = await storage.getLastVerificationCodeTime(email, "email_verification");
    if (lastCodeTime) {
      const timeSinceLastCode = Date.now() - lastCodeTime.getTime();
      if (timeSinceLastCode < 60000) {
        const secondsLeft = Math.ceil((60000 - timeSinceLastCode) / 1000);
        return sendError(res, `Подождите ${secondsLeft} секунд перед повторной отправкой`);
      }
    }

    const code = generateVerificationCode();
    await storage.createVerificationCode(email, code, "email_verification");

    const sent = await sendVerificationEmail(email, code);
    if (!sent) {
      return sendError(res, "Ошибка отправки email", 500);
    }

    return sendSuccess(res, { message: "Код отправлен на email" });
  } catch (error) {
    console.error("Send verification error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

const verifyEmailSchema = z.object({
  email: z.string().email("Некорректный email"),
  code: z.string().length(6, "Код должен содержать 6 цифр"),
});

authRouter.post("/verify-email", authLimiter, async (req: Request, res: Response) => {
  try {
    const validation = verifyEmailSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { email, code } = validation.data;

    const verificationCode = await storage.getValidVerificationCode(email, code, "email_verification");
    
    if (!verificationCode) {
      return sendError(res, "Неверный или истёкший код");
    }

    await storage.markVerificationCodeUsed(verificationCode.id);

    const user = await storage.getUserByEmail(email);
    if (!user) {
      return sendError(res, "Пользователь не найден", 404);
    }
    
    await storage.markEmailVerified(user.id);
    
    const token = generateToken({ userId: user.id, email: user.email });
    const { passwordHash, ...publicUser } = user;

    return sendSuccess(res, { 
      verified: true, 
      message: "Email успешно подтверждён",
      user: { ...publicUser, emailVerified: new Date() },
      token 
    });
  } catch (error) {
    console.error("Verify email error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

authRouter.post("/password-reset/request", emailLimiter, async (req: Request, res: Response) => {
  try {
    const validation = sendVerificationSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { email } = validation.data;

    const lastCodeTime = await storage.getLastVerificationCodeTime(email, "password_reset");
    if (lastCodeTime) {
      const timeSinceLastCode = Date.now() - lastCodeTime.getTime();
      if (timeSinceLastCode < 60000) {
        return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
      }
    }

    const user = await storage.getUserByEmail(email);
    if (!user) {
      return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
    }

    const code = generateVerificationCode();
    await storage.createVerificationCode(email, code, "password_reset");

    const sent = await sendPasswordResetEmail(email, code);
    if (!sent) {
      console.error("[password-reset] Failed to send email to:", email);
      return sendError(res, "Ошибка отправки email", 500);
    }

    return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
  } catch (error) {
    console.error("Password reset request error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

const passwordResetConfirmSchema = z.object({
  email: z.string().email("Некорректный email"),
  code: z.string().length(6, "Код должен содержать 6 цифр"),
  newPassword: z.string().min(8, "Пароль должен быть не менее 8 символов"),
});

authRouter.post("/password-reset/confirm", authLimiter, async (req: Request, res: Response) => {
  try {
    const validation = passwordResetConfirmSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { email, code, newPassword } = validation.data;

    const verificationCode = await storage.getValidVerificationCode(email, code, "password_reset");
    if (!verificationCode) {
      return sendError(res, "Неверный или истёкший код");
    }

    const user = await storage.getUserByEmail(email);
    if (!user) {
      return sendError(res, "Пользователь не найден", 404);
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    const updated = await storage.updateUserPassword(email, newPasswordHash);

    if (!updated) {
      return sendError(res, "Ошибка обновления пароля", 500);
    }

    await storage.markVerificationCodeUsed(verificationCode.id);

    return sendSuccess(res, { message: "Пароль успешно изменён" });
  } catch (error) {
    console.error("Password reset confirm error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});
