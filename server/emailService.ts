const UNISENDER_API_URL = "https://go2.unisender.ru/ru/transactional/api/v1/email/send.json";
const FROM_EMAIL = "noreply@shepot.online";
const FROM_NAME = "Шёпот";

export interface EmailOptions {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export async function sendEmail(options: EmailOptions): Promise<boolean> {
  try {
    // TEMPORARY: Hardcoded for testing - REMOVE after test!
    const apiKey = "66xz7h1tynh8dk699zmoxui8t1it81esh7f3uxza";
    
    if (!apiKey) {
      console.error("[emailService] UNISENDER_API_KEY not configured");
      return false;
    }

    const body = {
      message: {
        recipients: [{ email: options.to }],
        body: {
          html: options.html || options.text,
          plaintext: options.text,
        },
        subject: options.subject,
        from_email: FROM_EMAIL,
        from_name: FROM_NAME,
      },
    };

    const response = await fetch(UNISENDER_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": apiKey,
      },
      body: JSON.stringify(body),
    });

    const result = await response.json();

    if (result.status === "success") {
      console.log(`[emailService] Email sent to ${options.to}, job_id: ${result.job_id}`);
      return true;
    } else {
      console.error("[emailService] Unisender Go error:", result);
      return false;
    }
  } catch (error) {
    console.error("[emailService] Error sending email:", error);
    return false;
  }
}

export function generateVerificationCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function sendVerificationEmail(email: string, code: string): Promise<boolean> {
  return sendEmail({
    to: email,
    subject: "Код подтверждения — Шёпот",
    text: `Ваш код подтверждения: ${code}\nКод действителен 15 минут.\nЕсли вы не регистрировались в Шёпот, проигнорируйте это письмо.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Подтверждение email</h2>
        <p>Ваш код подтверждения:</p>
        <div style="font-size: 32px; font-weight: bold; color: #3B82F6; padding: 20px; background: #f5f5f5; border-radius: 8px; text-align: center; letter-spacing: 4px;">
          ${code}
        </div>
        <p style="color: #666; margin-top: 20px;">Код действителен 15 минут.</p>
        <p style="color: #999; font-size: 12px;">Если вы не регистрировались в Шёпот, проигнорируйте это письмо.</p>
      </div>
    `,
  });
}

export async function sendPasswordResetEmail(email: string, code: string): Promise<boolean> {
  return sendEmail({
    to: email,
    subject: "Сброс пароля — Шёпот",
    text: `Ваш код для сброса пароля: ${code}\nКод действителен 15 минут.\nЕсли вы не запрашивали сброс пароля, проигнорируйте это письмо.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Сброс пароля</h2>
        <p>Ваш код для сброса пароля:</p>
        <div style="font-size: 32px; font-weight: bold; color: #3B82F6; padding: 20px; background: #f5f5f5; border-radius: 8px; text-align: center; letter-spacing: 4px;">
          ${code}
        </div>
        <p style="color: #666; margin-top: 20px;">Код действителен 15 минут.</p>
        <p style="color: #999; font-size: 12px;">Если вы не запрашивали сброс пароля, проигнорируйте это письмо.</p>
      </div>
    `,
  });
}
