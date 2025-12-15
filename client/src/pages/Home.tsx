import { Badge } from "@/components/ui/badge";
import { useQuery } from "@tanstack/react-query";

export default function Home() {
  const { data: healthCheck, isLoading } = useQuery<{ success: boolean }>({
    queryKey: ["/api/auth/me"],
    retry: false,
  });

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-foreground mb-2" data-testid="text-title">
          BitChat API
        </h1>
        <p className="text-muted-foreground text-lg mb-4" data-testid="text-description">
          REST API сервер для мобильного мессенджера
        </p>
        <Badge 
          variant="outline" 
          className={isLoading ? "bg-amber-500/10 text-amber-600 border-amber-500/20" : "bg-green-500/10 text-green-600 border-green-500/20"}
          data-testid="badge-status"
        >
          {isLoading ? "Проверка..." : "API работает"}
        </Badge>
        <p className="text-sm text-muted-foreground mt-6">
          BitChat API v1.0
        </p>
      </div>
    </div>
  );
}
