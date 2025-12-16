import { WebSocket } from "ws";

export interface AuthenticatedWebSocket extends WebSocket {
  userId?: number;
  isAlive?: boolean;
  typingTimeouts?: Map<number, NodeJS.Timeout>;
}

export interface WSMessage {
  type: string;
  payload: any;
}
