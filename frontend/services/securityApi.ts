import { ApiResponseEnvelope } from '../modules/types';
import { auth, firebaseInitError, isFirebaseConfigured } from './firebase';
import { handleFirebaseApiRequest } from './firebaseApiRouter';

let inMemoryCsrfToken: string | null = null;
let expressBackendAvailable: boolean | null = null;

export function isExpressBackendOffline(): boolean {
  return expressBackendAvailable === false;
}

export function setCsrfToken(token: string | null) {
  inMemoryCsrfToken = token;
}

function readCsrfFromCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)mun_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function resolveApiUrl(path: string): string {
  const configuredBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
  if (!configuredBase || configuredBase === '/api') {
    return path;
  }
  if (configuredBase.endsWith('/api') && path.startsWith('/api/')) {
    return `${configuredBase}${path.slice(4)}`;
  }
  return `${configuredBase}${path}`;
}

export async function securityRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<ApiResponseEnvelope<T>> {
  // When signed into Firebase Auth, route directly to live Cloud Firestore.
  if (auth?.currentUser) {
    return handleFirebaseApiRequest<T>(path, options);
  }

  // If Firebase itself isn't configured and we already know no Express backend exists,
  // throw an explicit configuration error rather than falling back to offline/demo mode.
  if (!isFirebaseConfigured() && expressBackendAvailable === false) {
    throw new Error(
      firebaseInitError ||
        'Firebase is not configured. Check your VITE_FIREBASE_* environment variables.'
    );
  }

  // If no Express server is running on this deployment (e.g. static Vercel hosting),
  // require Firebase Authentication for protected endpoints rather than probing repeatedly.
  if (expressBackendAvailable === false && !path.startsWith('/api/auth/')) {
    throw new Error('Authentication required. Please sign in with Firebase.');
  }

  const method = (options.method || 'GET').toUpperCase();
  const csrf = inMemoryCsrfToken || readCsrfFromCookie();
  const targetUrl = resolveApiUrl(path);
  const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS || 8000);
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  let response: Response;
  try {
    response = await fetch(targetUrl, {
      ...options,
      credentials: 'include',
      signal: options.signal ?? controller?.signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(csrf && method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}),
        ...options.headers,
      },
    });
  } catch {
    if (timeoutId) clearTimeout(timeoutId);
    expressBackendAvailable = false;
    if (!isFirebaseConfigured()) {
      throw new Error(
        firebaseInitError ||
          'Neither a backend server nor Firebase configuration was detected.'
      );
    }
    throw new Error(
      'Backend API server is not connected. Sign in with Google to use live Firebase Firestore.'
    );
  }

  if (timeoutId) clearTimeout(timeoutId);

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (
    !isJson ||
    response.status === 404 ||
    response.status === 502 ||
    response.status === 504
  ) {
    expressBackendAvailable = false;
    if (!isFirebaseConfigured()) {
      throw new Error(
        firebaseInitError ||
          'Neither a backend server nor Firebase configuration was detected.'
      );
    }
    throw new Error(
      'Backend API server is not hosted on this deployment. Sign in with Google to connect directly to Firebase Firestore.'
    );
  }

  expressBackendAvailable = true;

  const payload = (await response.json()) as ApiResponseEnvelope<T>;
  if (!response.ok || !payload.success) {
    const err = new Error(payload.message || `Request failed (${response.status})`) as Error & {
      status?: number;
      errors?: Record<string, string[]>;
    };
    err.status = response.status;
    err.errors = payload.errors;
    throw err;
  }

  return payload;
}
