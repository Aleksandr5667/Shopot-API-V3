import { Router, Request, Response } from "express";
import { storage } from "../storage/index";
import { authenticateToken } from "../auth";
import { insertContactSchema } from "@shared/schema";
import { sendSuccess, sendError, parseLimit, parseCursor, contactsCursorSchema, getBaseUrl, withAbsoluteUrls } from "./utils";

export const contactsRouter = Router();

contactsRouter.get("/", authenticateToken, async (req: Request, res: Response) => {
  try {
    const limit = parseLimit(req.query.limit);
    const { cursor, error } = parseCursor(req.query.cursor, contactsCursorSchema);
    if (error) {
      return sendError(res, error);
    }
    
    const result = await storage.getContactsPaginated(req.user!.userId, limit, cursor);
    const baseUrl = getBaseUrl(req);
    return sendSuccess(res, { 
      contacts: withAbsoluteUrls(result.contacts, baseUrl),
      pageInfo: result.pageInfo
    });
  } catch (error) {
    console.error("Get contacts error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

contactsRouter.post("/", authenticateToken, async (req: Request, res: Response) => {
  try {
    const validation = insertContactSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const contactUser = await storage.getUserById(validation.data.contactUserId);
    if (!contactUser) {
      return sendError(res, "Пользователь не найден", 404);
    }

    if (validation.data.contactUserId === req.user!.userId) {
      return sendError(res, "Нельзя добавить себя в контакты");
    }

    const existingContacts = await storage.getContacts(req.user!.userId);
    const alreadyExists = existingContacts.some(
      (c) => c.contactUserId === validation.data.contactUserId
    );
    if (alreadyExists) {
      return sendError(res, "Контакт уже добавлен");
    }

    const contact = await storage.addContact(req.user!.userId, validation.data.contactUserId);
    return sendSuccess(res, { contact, contactUser }, 201);
  } catch (error) {
    console.error("Add contact error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

contactsRouter.delete("/:id", authenticateToken, async (req: Request, res: Response) => {
  try {
    const contactId = parseInt(req.params.id);
    if (isNaN(contactId)) {
      return sendError(res, "Некорректный ID контакта");
    }

    const deleted = await storage.removeContact(contactId, req.user!.userId);
    if (!deleted) {
      return sendError(res, "Контакт не найден", 404);
    }

    return sendSuccess(res, { deleted: true });
  } catch (error) {
    console.error("Delete contact error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});
