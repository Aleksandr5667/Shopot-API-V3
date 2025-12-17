import { storage } from "./storage/index";

interface ExpoPushMessage {
  to: string;
  sound: string;
  title: string;
  body: string;
  data?: Record<string, string>;
  badge?: number;
}

interface ExpoPushTicket {
  status: 'ok' | 'error';
  id?: string;
  message?: string;
  details?: { error?: string };
}

export class PushNotificationService {
  private readonly EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';

  async sendNewMessageNotification(
    recipientId: number,
    senderId: number,
    senderName: string,
    messageText: string,
    chatId: number
  ): Promise<boolean> {
    try {
      console.log(`[push] Attempting to send notification to user ${recipientId}`);
      const pushToken = await storage.getPushToken(recipientId);
      if (!pushToken) {
        console.log(`[push] No push token found for user ${recipientId}`);
        return false;
      }
      console.log(`[push] Found push token for user ${recipientId}: ${pushToken.substring(0, 30)}...`);

      if (!this.isValidExpoPushToken(pushToken)) {
        console.log(`[push] Invalid push token for user ${recipientId}`);
        return false;
      }

      const unreadCount = await storage.getUnreadMessagesCount(recipientId);

      const message: ExpoPushMessage = {
        to: pushToken,
        sound: 'notification',
        title: senderName,
        body: messageText,
        data: {
          chatId: chatId.toString(),
          senderId: senderId.toString(),
          type: 'new_message',
        },
        badge: unreadCount,
      };

      const result = await this.sendPushNotification(message);
      return result;
    } catch (error) {
      console.error(`[push] Error sending notification to user ${recipientId}:`, error);
      return false;
    }
  }

  private isValidExpoPushToken(token: string): boolean {
    return token.startsWith('ExponentPushToken[') || token.startsWith('ExpoPushToken[');
  }

  private async sendPushNotification(message: ExpoPushMessage): Promise<boolean> {
    try {
      const response = await fetch(this.EXPO_PUSH_URL, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Accept-encoding': 'gzip, deflate',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(message),
      });

      if (!response.ok) {
        console.error(`[push] Expo API error: ${response.status} ${response.statusText}`);
        return false;
      }

      const result = await response.json() as { data: ExpoPushTicket };
      
      if (result.data.status === 'error') {
        console.error(`[push] Push notification error:`, result.data.message, result.data.details);
        
        if (result.data.details?.error === 'DeviceNotRegistered') {
          console.log(`[push] Device not registered, token may need to be removed`);
        }
        return false;
      }

      console.log(`[push] Notification sent successfully`);
      return true;
    } catch (error) {
      console.error(`[push] Failed to send push notification:`, error);
      return false;
    }
  }
}

export const pushNotificationService = new PushNotificationService();
