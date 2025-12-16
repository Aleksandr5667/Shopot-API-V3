import { Server } from "http";
import { WebSocketService } from "./service";

export type { AuthenticatedWebSocket, WSMessage } from "./types";
export { WebSocketService } from "./service";

let wsService: WebSocketService | null = null;

export function initWebSocket(server: Server): WebSocketService {
  wsService = new WebSocketService(server);
  return wsService;
}

export function getWebSocketService(): WebSocketService | null {
  return wsService;
}
