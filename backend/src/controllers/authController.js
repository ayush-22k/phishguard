import { env } from '../config/env.js';
import { authService } from '../services/authService.js';

const refreshCookieName = 'phishguard_refresh';

function cookieOptions(expires) {
  return {
    httpOnly: true,
    // Chrome 80+ requires Secure when SameSite=None.
    // Chrome also allows the Secure attribute on http://localhost as a special
    // exemption (localhost is treated as a trustworthy origin by all major browsers).
    // This makes the cookie work cross-port in dev (5173→5000) AND in production (HTTPS).
    secure: true,
    sameSite: 'none',
    path: '/',
    expires,
  };
}

export function readCookie(request, name) {
  const rawCookie = request.headers?.cookie;
  if (!rawCookie) return null;
  const match = rawCookie.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${name}=`));
  if (!match) return null;
  try {
    return decodeURIComponent(match.slice(name.length + 1));
  } catch {
    return null;
  }
}

function authenticationResponse(response, result) {
  response.cookie(refreshCookieName, result.refreshToken, cookieOptions(result.refreshExpiresAt));
  return response.status(200).json({
    success: true,
    data: { user: result.user, accessToken: result.accessToken },
  });
}

export function createAuthController(service = authService) {
  return Object.freeze({
    async register(request, response) {
      const result = await service.register(request.body);
      // Keep the success shape identical when an email is already registered.
      // Registration is deliberately not an authentication event.
      const user = {
        name: result.registration.name,
        email: result.registration.email,
        role: 'USER',
        isVerified: false,
      };
      return response.status(201).json({ success: true, data: { user } });
    },

    async login(request, response) {
      return authenticationResponse(response, await service.login(request.body));
    },

    async refresh(request, response) {
      const refreshToken = readCookie(request, refreshCookieName);
      return authenticationResponse(response, await service.refresh(refreshToken));
    },

    async me(request, response) {
      return response.status(200).json({ success: true, data: { user: request.user } });
    },

    async logout(request, response) {
      await service.logout(request.auth?.sessionId);
      response.clearCookie(refreshCookieName, cookieOptions(new Date(0)));
      return response.status(204).send();
    },
  });
}

export const authController = createAuthController();
