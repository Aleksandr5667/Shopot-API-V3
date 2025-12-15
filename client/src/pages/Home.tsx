import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useQuery } from "@tanstack/react-query";

interface Endpoint {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  description: string;
  auth: boolean;
}

const endpoints: Endpoint[] = [
  { method: "POST", path: "/api/auth/register", description: "Регистрация нового пользователя", auth: false },
  { method: "POST", path: "/api/auth/login", description: "Авторизация пользователя", auth: false },
  { method: "GET", path: "/api/auth/me", description: "Получить текущего пользователя", auth: true },
  { method: "GET", path: "/api/users/search?email=", description: "Поиск пользователей по email", auth: true },
  { method: "PUT", path: "/api/users/profile", description: "Обновить профиль", auth: true },
  { method: "GET", path: "/api/users/online", description: "Получить список онлайн пользователей", auth: true },
  { method: "GET", path: "/api/users/:id/online", description: "Проверить онлайн статус пользователя", auth: true },
  { method: "GET", path: "/api/contacts", description: "Список контактов", auth: true },
  { method: "POST", path: "/api/contacts", description: "Добавить контакт", auth: true },
  { method: "DELETE", path: "/api/contacts/:id", description: "Удалить контакт", auth: true },
  { method: "GET", path: "/api/chats", description: "Список чатов с последним сообщением", auth: true },
  { method: "POST", path: "/api/chats", description: "Создать чат (личный или групповой)", auth: true },
  { method: "GET", path: "/api/chats/:id/messages", description: "Сообщения чата", auth: true },
  { method: "POST", path: "/api/messages", description: "Отправить сообщение", auth: true },
  { method: "PUT", path: "/api/messages/:id", description: "Редактировать сообщение", auth: true },
  { method: "DELETE", path: "/api/messages/:id", description: "Удалить сообщение и медиа-файл", auth: true },
  { method: "PUT", path: "/api/messages/:id/read", description: "Отметить сообщение прочитанным", auth: true },
  { method: "GET", path: "/api/messages/search?q=", description: "Поиск сообщений", auth: true },
  { method: "POST", path: "/api/upload", description: "Получить URL для загрузки файла", auth: true },
  { method: "PUT", path: "/api/media/finalize", description: "Завершить загрузку медиа", auth: true },
  { method: "GET", path: "/api/media/:key", description: "Получить медиафайл", auth: false },
];

function getMethodColor(method: string): string {
  switch (method) {
    case "GET":
      return "bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20";
    case "POST":
      return "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20";
    case "PUT":
      return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20";
    case "DELETE":
      return "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20";
    default:
      return "bg-gray-500/10 text-gray-600 dark:text-gray-400 border-gray-500/20";
  }
}

export default function Home() {
  const { data: healthCheck, isLoading } = useQuery<{ success: boolean }>({
    queryKey: ["/api/auth/me"],
    retry: false,
  });

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-foreground mb-2" data-testid="text-title">
            BitChat API
          </h1>
          <p className="text-muted-foreground text-lg" data-testid="text-description">
            REST API сервер для мобильного мессенджера
          </p>
          <div className="flex items-center justify-center gap-2 mt-4">
            <Badge 
              variant="outline" 
              className={isLoading ? "bg-amber-500/10 text-amber-600 border-amber-500/20" : "bg-green-500/10 text-green-600 border-green-500/20"}
              data-testid="badge-status"
            >
              {isLoading ? "Проверка..." : "API работает"}
            </Badge>
          </div>
        </div>

        <Card className="mb-6" data-testid="card-auth-info">
          <CardHeader>
            <CardTitle className="text-lg">Авторизация</CardTitle>
            <CardDescription>
              Используйте JWT токен в заголовке Authorization
            </CardDescription>
          </CardHeader>
          <CardContent>
            <code className="block bg-muted p-3 rounded-md text-sm text-muted-foreground">
              Authorization: Bearer &lt;token&gt;
            </code>
          </CardContent>
        </Card>

        <Card className="mb-6" data-testid="card-response-format">
          <CardHeader>
            <CardTitle className="text-lg">Формат ответа</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Успешный ответ:</p>
              <code className="block bg-muted p-3 rounded-md text-sm text-muted-foreground">
                {`{ "success": true, "data": { ... } }`}
              </code>
            </div>
            <div>
              <p className="text-sm text-muted-foreground mb-1">Ошибка:</p>
              <code className="block bg-muted p-3 rounded-md text-sm text-muted-foreground">
                {`{ "success": false, "error": "сообщение об ошибке" }`}
              </code>
            </div>
          </CardContent>
        </Card>

        <Card data-testid="card-endpoints">
          <CardHeader>
            <CardTitle className="text-lg">Эндпоинты</CardTitle>
            <CardDescription>
              Все доступные API маршруты
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-auto">
              <div className="space-y-2">
                {endpoints.map((endpoint, index) => (
                  <div key={index}>
                    <div 
                      className="flex items-center gap-3 py-2 px-3 rounded-md hover-elevate"
                      data-testid={`endpoint-${endpoint.method.toLowerCase()}-${endpoint.path.replace(/[/:]/g, '-')}`}
                    >
                      <Badge 
                        variant="outline" 
                        className={`font-mono text-xs min-w-[60px] justify-center ${getMethodColor(endpoint.method)}`}
                      >
                        {endpoint.method}
                      </Badge>
                      <code className="text-sm font-mono text-foreground flex-1">
                        {endpoint.path}
                      </code>
                      {endpoint.auth && (
                        <Badge variant="secondary" className="text-xs">
                          AUTH
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground ml-[76px] mb-2">
                      {endpoint.description}
                    </p>
                    {index < endpoints.length - 1 && <Separator className="my-1" />}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <div className="text-center mt-8 text-sm text-muted-foreground">
          <p>BitChat API v1.0 • Node.js + Express + PostgreSQL</p>
        </div>
      </div>
    </div>
  );
}
