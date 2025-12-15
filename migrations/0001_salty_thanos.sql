CREATE TYPE "public"."member_role" AS ENUM('admin', 'member');--> statement-breakpoint
CREATE TYPE "public"."upload_status" AS ENUM('pending', 'uploading', 'completed', 'failed', 'expired');--> statement-breakpoint
ALTER TYPE "public"."message_type" ADD VALUE 'system';--> statement-breakpoint
CREATE TABLE "upload_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"filename" text NOT NULL,
	"file_size" integer NOT NULL,
	"mime_type" text NOT NULL,
	"chunk_size" integer DEFAULT 1048576 NOT NULL,
	"total_chunks" integer NOT NULL,
	"uploaded_chunks" integer[] DEFAULT ARRAY[]::integer[] NOT NULL,
	"status" "upload_status" DEFAULT 'pending' NOT NULL,
	"category" text DEFAULT 'files' NOT NULL,
	"object_path" text,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
ALTER TABLE "chat_members" ADD COLUMN "role" "member_role" DEFAULT 'member' NOT NULL;--> statement-breakpoint
ALTER TABLE "chat_members" ADD COLUMN "added_by" integer;--> statement-breakpoint
ALTER TABLE "chats" ADD COLUMN "description" text;--> statement-breakpoint
ALTER TABLE "chats" ADD COLUMN "avatar_url" text;--> statement-breakpoint
ALTER TABLE "chats" ADD COLUMN "updated_at" timestamp DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "chats" ADD COLUMN "max_members" integer DEFAULT 256 NOT NULL;--> statement-breakpoint
ALTER TABLE "messages" ADD COLUMN "edited" timestamp;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "push_token" text;--> statement-breakpoint
ALTER TABLE "upload_sessions" ADD CONSTRAINT "upload_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chat_members" ADD CONSTRAINT "chat_members_added_by_users_id_fk" FOREIGN KEY ("added_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;