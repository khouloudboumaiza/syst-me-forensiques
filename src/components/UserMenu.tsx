// src/components/UserMenu.tsx
// Composant dynamique d'affichage de l'utilisateur connecté dans la navbar.
// Connecté à useAuth() — ne crée pas d'état parallèle.

import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useRef, useEffect, useState } from "react";
import { CircleUser, LogOut, Shield, ChevronDown } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";

/** Formate le rôle technique en libellé lisible. */
function formatRole(role: string | undefined): string {
  if (!role) return "Forensique";
  const map: Record<string, string> = {
    admin: "Administrateur",
    analyst: "Analyste SOC",
    analyste: "Analyste SOC",
  };
  return map[role.toLowerCase()] ?? role;
}

export function UserMenu() {
  const { user, logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const handleLogout = useCallback(() => {
    // 1. Vider tout le cache TanStack Query (données SOC sensibles)
    queryClient.clear();
    // 2. Déconnecter via AuthContext (supprime les tokens sessionStorage)
    logout();
    // 3. Rediriger vers la page de connexion
    navigate({ to: "/login" });
  }, [logout, navigate, queryClient]);

  // Si l'utilisateur n'est pas authentifié, on n'affiche rien
  // (le AuthGuard dans __root.tsx gérera la redirection)
  if (!isAuthenticated) {
    return null;
  }

  // État de chargement : isAuthenticated mais user est encore null
  if (!user) {
    return (
      <div className="flex items-center gap-2 pl-3 border-l border-border">
        <Skeleton className="h-6 w-6 rounded-full" />
        <div className="space-y-1">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-3 w-14" />
        </div>
      </div>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          id="user-menu-trigger"
          className="flex items-center gap-2 pl-3 border-l border-border rounded-sm hover:bg-muted px-2 py-1 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
          aria-label="Menu utilisateur"
        >
          <CircleUser className="h-6 w-6 text-muted-foreground flex-shrink-0" />
          <div className="text-xs text-left">
            <div className="font-medium leading-tight max-w-[100px] truncate">
              {user.username}
            </div>
            <div className="text-muted-foreground leading-tight">
              {formatRole(user.role)}
            </div>
          </div>
          <ChevronDown className="h-3 w-3 text-muted-foreground ml-1" />
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-52" sideOffset={8}>
        {/* En-tête : identité complète */}
        <DropdownMenuLabel className="pb-2">
          <div className="flex items-center gap-2.5">
            <div className="inline-flex items-center justify-center h-8 w-8 rounded-full bg-primary/10 border border-primary/20 flex-shrink-0">
              <CircleUser className="h-4 w-4 text-primary" />
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-semibold truncate">{user.username}</p>
              <p className="text-xs text-muted-foreground truncate flex items-center gap-1">
                <Shield className="h-3 w-3 inline-block flex-shrink-0" />
                {formatRole(user.role)}
              </p>
            </div>
          </div>
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        {/* Déconnexion */}
        <DropdownMenuItem
          id="logout-button"
          onClick={handleLogout}
          className="text-destructive focus:text-destructive focus:bg-destructive/10 cursor-pointer gap-2"
        >
          <LogOut className="h-4 w-4" />
          Déconnexion
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
