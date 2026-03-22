const BASE = "/latticeguard-api";

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body: unknown) => request<T>("POST", path, body),
};
