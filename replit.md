# BitChat API Server

## Overview
REST API server for the BitChat mobile messenger application. Built with Node.js, Express, PostgreSQL, and Replit Object Storage for media files. Includes WebSocket support for real-time messaging.

## Technology Stack
- **Runtime:** Node.js 20
- **Framework:** Express.js
- **Database:** PostgreSQL (Neon)
- **ORM:** Drizzle ORM
- **Authentication:** JWT (jsonwebtoken)
- **Password Hashing:** bcrypt
- **File Storage:** Replit Object Storage (Google Cloud Storage)
- **Real-time:** WebSocket (ws library)
- **Validation:** Zod

## Database Schema

### Tables
1. **users** - User accounts
   - id, email, password_hash, display_name, avatar_color, avatar_url, bio, created_at, last_seen

2. **contacts** - User contacts
   - id, user_id, contact_user_id, created_at

3. **chats** - Chat rooms (private and group)
   - id, type (private/group), name, description, avatar_color, avatar_url, max_members, created_at, created_by

4. **chat_members** - Chat participants with roles
   - id, chat_id, user_id, role (admin/member), added_by, is_muted, muted_until, joined_at

5. **messages** - Chat messages
   - id, chat_id, sender_id, content, type (text/image/video/voice/system), media_url, created_at, read_by

6. **message_receipts** - Message delivery tracking
   - id, message_id, user_id, delivered_at, created_at

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user (requires auth)

### Users
- `GET /api/users/search?email=` - Search users by email
- `PUT /api/users/profile` - Update profile
- `GET /api/users/online` - Get list of online users
- `GET /api/users/:id/online` - Check if specific user is online

### Contacts
- `GET /api/contacts` - Get contact list
- `POST /api/contacts` - Add contact
- `DELETE /api/contacts/:id` - Remove contact

### Chats
- `GET /api/chats` - Get chat list with last message
- `POST /api/chats` - Create chat (private or group, includes description for groups)
- `GET /api/chats/:id/messages` - Get chat messages
- `GET /api/chats/:id/details` - Get chat with all members and roles
- `PATCH /api/chats/:id` - Update group chat (name, description) - admin only
- `DELETE /api/chats/:id` - Delete chat with all messages and media files (member only)
- `POST /api/chats/:id/members` - Add members to group - admin only
- `DELETE /api/chats/:id/members/:userId` - Remove member from group - admin only
- `POST /api/chats/:id/leave` - Leave group chat
- `POST /api/chats/:id/avatar` - Update group avatar - admin only

### Messages
- `POST /api/messages` - Send message
- `PUT /api/messages/:id` - Edit message (owner only)
- `DELETE /api/messages/:id` - Delete message and associated media file from Object Storage (any chat member)
- `PUT /api/messages/:id/delivered` - Mark message as delivered (creates delivery receipt)
- `PUT /api/messages/:id/read` - Mark message as read
- `GET /api/messages/search?q=` - Search messages in user's chats

### Media
- `POST /api/upload` - Get upload URL for file
- `PUT /api/media/finalize` - Finalize uploaded media with ACL
- `GET /api/media/:key` - Get media file

## WebSocket

### Connection
Connect to WebSocket with JWT token:
```
ws://<host>/ws?token=<jwt_token>
```

### Events (Server → Client)
- `new_message` - New message received
- `message:delivered` - Message was delivered to a recipient
- `message_updated` - Message was edited
- `message_deleted` - Message was deleted
- `chat_deleted` - Chat was deleted
- `chat_updated` - Group chat was updated (name/description)
- `members_added` - Members added to group
- `member_removed` - Member removed from group
- `removed_from_chat` - You were removed from a group
- `member_left` - Member left the group
- `user_online` - User came online
- `user_offline` - User went offline
- `typing` - User is typing

### Events (Client → Server)
- `typing` - Send typing indicator
  ```json
  { "type": "typing", "chatId": 123 }
  ```

## Response Format

### Success
```json
{
  "success": true,
  "data": { ... }
}
```

### Error
```json
{
  "success": false,
  "error": "Error message in Russian"
}
```

## Authentication
All protected endpoints require JWT token in Authorization header:
```
Authorization: Bearer <token>
```

Token expires in 7 days.

## Running the Project
```bash
npm run dev
```

This starts both the Express backend and Vite frontend server on port 5000.

## Database Commands
```bash
npm run db:push  # Push schema changes to database
```

## Project Structure
```
├── client/                 # Frontend (React + Vite)
│   └── src/
│       ├── pages/         # Page components
│       └── components/    # UI components
├── server/
│   ├── index.ts          # Express server entry
│   ├── routes.ts         # API routes
│   ├── storage.ts        # Database storage layer
│   ├── auth.ts           # JWT authentication
│   ├── websocket.ts      # WebSocket service
│   ├── objectStorage.ts  # Object storage service
│   └── db.ts             # Database connection
├── shared/
│   └── schema.ts         # Drizzle schema & types
└── package.json
```

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `SESSION_SECRET` - JWT secret key
- `PUBLIC_OBJECT_SEARCH_PATHS` - Object storage public paths
- `PRIVATE_OBJECT_DIR` - Object storage private directory

## Recent Changes (December 08, 2025)
- **Message Delivery Tracking System**
  - Added `message_receipts` table for tracking message delivery
  - Added `PUT /api/messages/:id/delivered` endpoint for confirming message delivery
  - Added `message:delivered` WebSocket event for real-time delivery notifications
  - Messages now automatically create delivery receipts for all chat members (except sender)
  - `GET /api/chats/:id/messages` now includes `deliveredTo` array with user IDs

- **Previous Features**
  - Added avatarUrl field to user profile (nullable string for custom avatar images)
  - Added WebSocket support for real-time messaging
  - Added message editing and deletion endpoints
  - Added message search endpoint
  - Added online status endpoints
  - PostgreSQL database with Drizzle ORM
  - JWT authentication with bcrypt password hashing
  - Object Storage integration for media files
  - CORS enabled for mobile app integration
  - Russian error messages for mobile app compatibility
