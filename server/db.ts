import { Pool, neonConfig } from '@neondatabase/serverless';
import { neon } from '@neondatabase/serverless';
import { drizzle as drizzleServerless } from 'drizzle-orm/neon-serverless';
import { drizzle as drizzleHttp } from 'drizzle-orm/neon-http';
import ws from "ws";
import * as schema from "@shared/schema";

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

// In production, use HTTP-based connection to avoid WebSocket/helium proxy issues
// In development, use WebSocket through Replit's internal proxy for better performance
const isProduction = process.env.NODE_ENV === 'production';

let db: ReturnType<typeof drizzleServerless> | ReturnType<typeof drizzleHttp>;
let pool: Pool | null = null;

if (isProduction) {
  // HTTP-based connection for production - no WebSocket needed
  const sql = neon(process.env.DATABASE_URL);
  db = drizzleHttp({ client: sql, schema });
} else {
  // WebSocket-based connection for development
  neonConfig.webSocketConstructor = ws;
  pool = new Pool({ connectionString: process.env.DATABASE_URL });
  db = drizzleServerless({ client: pool, schema });
}

export { db, pool };
