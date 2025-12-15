# BitChat API Server Design Guidelines

## Project Context
This is a **backend API server** for the BitChat mobile messenger. The mobile application (Expo/React Native) is already complete - this project requires **no visual design or frontend components**. These guidelines focus on API architecture and response structure.

---

## API Design Principles

### 1. Response Structure
**Consistent JSON Format:**
```
Success: { success: true, data: {...} }
Error: { success: false, error: "message" }
```

**HTTP Status Codes:**
- 200: Success
- 201: Created
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Server Error

### 2. Authentication Flow
- JWT tokens in `Authorization: Bearer <token>` header
- Token expiration: 7 days
- Password requirements: minimum 8 characters
- Return user object + token on login/register

### 3. Data Formatting Standards

**Timestamps:** ISO 8601 format (`created_at`, `last_seen`, `joined_at`)

**User Objects:** Always include: id, email, display_name, avatar_color, bio, last_seen

**Chat Objects:** Include: id, type, name, avatar_color, created_at, last_message (preview)

**Message Objects:** Include: id, chat_id, sender (full user object), content, type, media_url, created_at, read_by

### 4. Pagination & Limits
- Messages: 50 per page, newest first
- Chats: Return all with last message
- Contacts: Return all
- Search: Limit 20 results

### 5. Media Handling
- Accepted formats: JPEG/PNG (images), MP4/MOV (video), MP3/WAV (voice)
- Max sizes: Images 10MB, Video 50MB, Voice 5MB
- Return signed URLs valid for 24 hours
- Store with unique keys: `{userId}/{timestamp}_{filename}`

### 6. Error Messages (Russian)
- "Пользователь не найден"
- "Неверный пароль"
- "Email уже зарегистрирован"
- "Чат не найден"
- "Недопустимый формат файла"

### 7. Real-time Considerations
- Include `last_seen` timestamp for online status
- Return `read_by` arrays for message status
- Support for future WebSocket integration (structure accordingly)

---

**Critical:** All endpoints must validate JWT tokens (except /auth/register and /auth/login), sanitize inputs, and return Russian error messages for mobile app compatibility.