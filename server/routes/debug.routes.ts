import { Router, Request, Response } from "express";
import { getWebSocketService } from "../websocket";
import { sendSuccess } from "./utils";

export const debugRouter = Router();

debugRouter.get("/memory", async (_req: Request, res: Response) => {
  const memUsage = process.memoryUsage();
  const wsService = getWebSocketService();
  
  return sendSuccess(res, {
    memory: {
      rss: `${Math.round(memUsage.rss / 1024 / 1024)} MB`,
      heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)} MB`,
      external: `${Math.round(memUsage.external / 1024 / 1024)} MB`,
    },
    websocket: {
      connectedUsers: wsService?.getOnlineUsers().length || 0,
    },
    uptime: `${Math.round(process.uptime())} seconds`,
  });
});
