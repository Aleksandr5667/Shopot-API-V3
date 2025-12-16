import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes/index";
import { serveStatic } from "./static";
import { createServer } from "http";
import { initWebSocket } from "./websocket";

const app = express();
const httpServer = createServer(app);

// Trust proxy for rate limiting behind reverse proxy (Replit, etc.)
app.set("trust proxy", 1);

// Initialize WebSocket server
initWebSocket(httpServer);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

app.use(
  express.json({
    limit: '2mb',
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api") || path.startsWith("/objects/")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      
      // Security: Don't log sensitive auth responses (tokens, passwords, user data)
      const sensitiveEndpoints = ["/api/auth/login", "/api/auth/register", "/api/auth/me"];
      const isSensitive = sensitiveEndpoints.some(ep => path.startsWith(ep));
      
      // Log file size for /objects/ requests
      if (path.startsWith("/objects/")) {
        const contentLength = res.getHeader("Content-Length");
        if (contentLength) {
          const sizeMB = (parseInt(contentLength as string) / 1024 / 1024).toFixed(2);
          logLine += ` [${sizeMB} MB]`;
        }
      }
      
      if (capturedJsonResponse && !isSensitive) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  await registerRoutes(httpServer, app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      log(`serving on port ${port}`);
    },
  );
})();
