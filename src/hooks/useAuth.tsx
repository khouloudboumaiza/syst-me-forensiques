// src/hooks/useAuth.tsx
// Contexte d'authentification ForensiQ.
// Le token JWT est stocké en sessionStorage (effacé en fermant le navigateur).

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const TOKEN_KEY = "forensiq_access_token";
const REFRESH_KEY = "forensiq_refresh_token";
const USER_KEY = "forensiq_user";

interface AuthUser {
  username: string;
  role: string;
}

interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const isBrowser = typeof window !== "undefined";

const getSessionItem = (key: string): string | null => {
  if (!isBrowser) return null;
  try {
    return sessionStorage.getItem(key);
  } catch (e) {
    return null;
  }
};

const setSessionItem = (key: string, value: string): void => {
  if (!isBrowser) return;
  try {
    sessionStorage.setItem(key, value);
  } catch (e) {}
};

const removeSessionItem = (key: string): void => {
  if (!isBrowser) return;
  try {
    sessionStorage.removeItem(key);
  } catch (e) {}
};

const clearSession = (): void => {
  if (!isBrowser) return;
  try {
    sessionStorage.clear();
  } catch (e) {}
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken]   = useState<string | null>(() => getSessionItem(TOKEN_KEY));
  const [user, setUser]     = useState<AuthUser | null>(() => {
    const raw = getSessionItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  });

  const login = useCallback(async (username: string, password: string) => {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail ?? "Identifiants invalides");
    }
    const data = await res.json();
    setSessionItem(TOKEN_KEY, data.access_token);
    setSessionItem(REFRESH_KEY, data.refresh_token);
    setSessionItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role }));
    setToken(data.access_token);
    setUser({ username: data.username, role: data.role });
  }, []);

  const logout = useCallback(() => {
    removeSessionItem(TOKEN_KEY);
    removeSessionItem(REFRESH_KEY);
    removeSessionItem(USER_KEY);
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

// Helper: fetch avec Authorization header automatique
export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getSessionItem(TOKEN_KEY);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> ?? {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });

  // Token expiré → essayer de rafraîchir
  if (res.status === 401) {
    const refreshToken = getSessionItem(REFRESH_KEY);
    if (refreshToken) {
      const rRes = await fetch(`${API_URL}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (rRes.ok) {
        const rData = await rRes.json();
        setSessionItem(TOKEN_KEY, rData.access_token);
        headers["Authorization"] = `Bearer ${rData.access_token}`;
        return fetch(`${API_URL}${path}`, { ...options, headers });
      }
    }
    // Refresh échoué → forcer logout
    clearSession();
    if (isBrowser) {
      window.location.href = "/login";
    }
  }
  return res;
}
