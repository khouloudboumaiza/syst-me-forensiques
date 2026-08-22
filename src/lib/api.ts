export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const TOKEN_KEY = "forensiq_access_token";
const REFRESH_KEY = "forensiq_refresh_token";

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

const clearSession = (): void => {
  if (!isBrowser) return;
  try {
    sessionStorage.clear();
  } catch (e) {}
};

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getSessionItem(TOKEN_KEY);
  const baseHeaders: Record<string, string> = {
    ...(options.headers as Record<string, string> ?? {}),
  };
  if (token) baseHeaders["Authorization"] = `Bearer ${token}`;
  if (options.body && !(options.body instanceof FormData) && !baseHeaders["Content-Type"]) {
    baseHeaders["Content-Type"] = "application/json";
  }

  const res = await fetch(`${API_URL}${path}`, { ...options, headers: baseHeaders });

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
        baseHeaders["Authorization"] = `Bearer ${rData.access_token}`;
        return fetch(`${API_URL}${path}`, { ...options, headers: baseHeaders });
      }
    }
    clearSession();
    if (isBrowser) {
      window.location.href = "/login";
    }
  }
  return res;
}