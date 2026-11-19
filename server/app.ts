import express, { NextFunction, Request, Response } from 'express';
import * as OTPAuth from 'otpauth';
import {
  decryptSensitiveField,
  encryptSensitiveField,
  generateCaptchaChallenge,
  generateNumericOtp,
  generateToken,
  hashPassword,
  hmacOtp,
  maskAadhaar,
  parseCookies,
  sanitizeText,
  sha256,
  verifyPassword,
} from './crypto';
import {
  ALL_MODULES,
  ALL_PERMISSION_TYPES,
  CSC_OPERATOR_PERMISSION_KEYS,
  MAX_REMEMBER_ME_MS,
  REPORT_PERMISSION_KEYS,
  ROLE_PERMISSION_MATRIX,
  SecurityStore,
} from './securityStore';
import {
  AccountStatus,
  ModuleKey,
  PermissionType,
  ReportPermissionKey,
  RoleName,
  ServerSession,
  ServerUser,
} from './types';

import { Phase03Store } from './phase03Store';
import { registerPhase03Routes } from './phase03Routes';
import { ErpStore } from './erpStore';
import { registerErpRoutes } from './erpRoutes';
import { FinanceStore } from './finance/financeStore';
import { registerFinanceRoutes } from './finance/financeRoutes';
import { ReportStore } from './reports/reportStore';
import { ReportDataEngine } from './reports/reportDataEngine';
import { ReportSchedulerService } from './reports/reportScheduler';
import { registerReportRoutes } from './reports/reportRoutes';
import { Phase08Store } from './phase08/phase08Store';
import { BackupSchedulerService } from './phase08/backupScheduler';
import { registerPhase08Routes } from './phase08/phase08Routes';
import { parsePrivacyDeviceMetadata } from './phase08/phase08Crypto';
import { OtpChannel } from './phase08/phase08Types';
import { QaStore } from './phase09/qaStore';
import { registerQaRoutes } from './phase09/qaRoutes';
import { CscStore } from './cscStore';
import { registerCscRoutes } from './cscRoutes';

interface AuthedRequest extends Request {
  authUser?: ServerUser;
  authSession?: ServerSession;
}

export interface CreateAppOptions {
  enableRateLimit?: boolean;
  maxAuthRequestsPerMinute?: number;
  phase03Store?: Phase03Store;
  erpStore?: ErpStore;
  financeStore?: FinanceStore;
  reportStore?: ReportStore;
  phase08Store?: Phase08Store;
  qaStore?: QaStore;
  cscStore?: CscStore;
  enableReportScheduler?: boolean;
  enableBackupScheduler?: boolean;
}

function validateStrongPassword(password: unknown): string | null {
  const pwd = typeof password === 'string' ? password : '';
  if (pwd.length < 12) {
    return 'Strong Password Policy requires at least 12 characters.';
  }
  if (!/[A-Z]/.test(pwd) || !/[a-z]/.test(pwd) || !/[0-9]/.test(pwd) || !/[^A-Za-z0-9]/.test(pwd)) {
    return 'Strong Password Policy requires uppercase, lowercase, number, and special character.';
  }
  return null;
}

const SESSION_COOKIE = 'mun_session';
const CSRF_COOKIE = 'mun_csrf';

function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '127.0.0.1';
}

function getDeviceInfo(req: Request): string {
  const ua = req.headers['user-agent'];
  return typeof ua === 'string' && ua.length > 0 ? ua.slice(0, 140) : 'Unknown Client';
}

function isSmsOrEmailConfigured(): boolean {
  return Boolean(process.env.SMTP_HOST || process.env.SMS_API_KEY);
}

function apiSuccess(res: Response, data: unknown, message = 'OK', status = 200) {
  return res.status(status).json({
    success: true,
    message,
    data,
    meta: {
      timestamp: new Date().toISOString(),
    },
  });
}

function apiError(
  res: Response,
  message: string,
  status = 400,
  errors?: Record<string, string[]>
) {
  return res.status(status).json({
    success: false,
    message,
    data: null,
    meta: {
      timestamp: new Date().toISOString(),
    },
    ...(errors ? { errors } : {}),
  });
}

export function createApp(
  store: SecurityStore = new SecurityStore(),
  options: CreateAppOptions = {}
) {
  const app = express();
  const phase03Store = options.phase03Store ?? new Phase03Store();
  const erpStore = options.erpStore ?? new ErpStore(store, phase03Store);
  const financeStore = options.financeStore ?? new FinanceStore(store, phase03Store, erpStore);
  const reportStore = options.reportStore ?? new ReportStore();
  const cscStore = options.cscStore ?? new CscStore();
  const reportDataEngine = new ReportDataEngine(
    store,
    phase03Store,
    erpStore,
    financeStore,
    reportStore,
    cscStore
  );
  const reportScheduler = new ReportSchedulerService(store, phase03Store, reportStore, reportDataEngine);
  const phase08Store =
    options.phase08Store ?? new Phase08Store(store, phase03Store, erpStore, financeStore, reportStore);
  const backupScheduler = new BackupSchedulerService(phase08Store);
  const qaStore = options.qaStore ?? new QaStore();
  app.locals.cscStore = cscStore;

  // Merge Phase 08 Custom Role & Active Temporary Permissions into SecurityStore
  store.setExternalPermissionResolver((userId, customRoleCode) => {
    const merged: Record<string, boolean> = {};
    if (customRoleCode) {
      const cRole = phase08Store.customRoles.find(
        (r) => r.roleCode === customRoleCode && r.status === 'ACTIVE'
      );
      if (cRole) {
        Object.assign(merged, cRole.permissions);
      }
    }
    const temp = phase08Store.getEffectiveTemporaryPermissions(userId);
    Object.assign(merged, temp);
    return merged;
  });

  app.locals.phase08Store = phase08Store;
  app.locals.qaStore = qaStore;

  const enableRateLimit = options.enableRateLimit ?? true;
  const maxAuthReqs = options.maxAuthRequestsPerMinute ?? 40;

  app.use(express.json({ limit: '16mb' }));

  // Baseline Security Headers against XSS, MIME sniffing, Clickjacking
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    next();
  });

  // Rate limiting middleware for /api/auth/*
  const authRateLimiter = (req: Request, res: Response, next: NextFunction) => {
    if (!enableRateLimit) return next();
    const key = `auth:${getClientIp(req)}`;
    const now = Date.now();
    const bucket = store.rateLimitBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      store.rateLimitBuckets.set(key, { count: 1, resetAt: now + 60_000 });
      return next();
    }
    bucket.count += 1;
    if (bucket.count > maxAuthReqs) {
      return apiError(
        res,
        'Too many authentication requests. Please wait a minute and retry.',
        429
      );
    }
    return next();
  };

  // Authentication & Session Expiration Middleware
  const requireAuth = (req: AuthedRequest, res: Response, next: NextFunction) => {
    const cookies = parseCookies(req.headers.cookie);
    const cookieToken = cookies[SESSION_COOKIE];
    const authHeader = req.headers.authorization;
    const bearerToken =
      typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7).trim()
        : undefined;

    const rawToken = cookieToken || bearerToken;
    if (!rawToken) {
      return apiError(res, 'Authentication required.', 401);
    }

    const tokenHash = sha256(rawToken);
    const session = store.sessions.get(tokenHash);
    if (!session) {
      return apiError(res, 'Invalid session token.', 401);
    }

    if (session.status !== 'ACTIVE') {
      return apiError(res, 'Session has been invalidated.', 401);
    }

    const now = Date.now();
    // Enforce server-side absolute cap (Remember Me max 240 minutes, never silently extended)
    if (session.expiresAt <= now || session.maxAllowedExpiresAt <= now) {
      session.status = 'EXPIRED';
      store.addSecurityLog({
        actorUserId: session.userId,
        eventType: 'SESSION_EXPIRED',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Session ${session.id} expired (${session.rememberMe ? '240-min Remember Me limit' : 'standard window'} reached).`,
      });
      return apiError(res, 'Session expired. Please sign in again.', 401);
    }

    // Idle session protection for non-Remember-Me sessions (60 min idle cutoff)
    const lastActiveMs = Date.parse(session.lastActiveAt || session.createdAt);
    if (!session.rememberMe && Number.isFinite(lastActiveMs) && now - lastActiveMs > store.sessionTtlMs) {
      session.status = 'EXPIRED';
      store.addSecurityLog({
        actorUserId: session.userId,
        eventType: 'SESSION_EXPIRED',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Session ${session.id} expired due to inactivity.`,
      });
      return apiError(res, 'Session expired due to inactivity. Please sign in again.', 401);
    }

    const user = store.findUserByUserId(session.userId);
    if (!user || user.status !== 'ACTIVE') {
      session.status = 'REVOKED';
      return apiError(res, 'User account is not active.', 401);
    }

    // CSRF Protection for state-changing requests authenticated via cookies
    if (
      cookieToken &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method.toUpperCase())
    ) {
      const csrfCookie = cookies[CSRF_COOKIE];
      const csrfHeader = req.headers['x-csrf-token'];
      if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
        return apiError(res, 'Invalid or missing CSRF token.', 403);
      }
    }

    session.lastActiveAt = new Date(now).toISOString();
    // Note: session.expiresAt is NEVER silently extended past session.maxAllowedExpiresAt
    req.authUser = user;
    req.authSession = session;
    return next();
  };

  const requirePermission =
    (mod: ModuleKey, perm: PermissionType) =>
    (req: AuthedRequest, res: Response, next: NextFunction) => {
      const user = req.authUser;
      if (!user) return apiError(res, 'Unauthorized.', 401);

      if (!store.hasPermission(user, mod, perm)) {
        store.addSecurityLog({
          actorUserId: user.userId,
          eventType: 'UNAUTHORIZED_ACCESS',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Blocked ${user.role} access to ${mod}.${perm} (${req.method} ${req.path}).`,
        });
        phase08Store.raiseSecurityAlert({
          category: 'UNAUTHORIZED_ACCESS',
          severity: 'MEDIUM',
          title: `Unauthorized Access Blocked: ${user.userId}`,
          description: `Role ${user.role} blocked from ${mod}.${perm} at ${req.method} ${req.path}.`,
          relatedUserId: user.userId,
        });
        phase08Store.recordBeforeAfterAudit({
          userId: user.userId,
          userRole: user.role,
          actionType: 'UNAUTHORIZED_MODULE_ACCESS',
          module: mod,
          recordId: `${mod}.${perm}`,
          beforeValues: null,
          afterValues: { blocked: true, method: req.method, path: req.path },
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          actionResult: 'BLOCKED',
        });
        return apiError(
          res,
          `Forbidden: ${user.role} lacks ${mod}.${perm} permission.`,
          403
        );
      }
      return next();
    };

  const setSessionCookies = (
    res: Response,
    rawToken: string,
    csrfToken: string,
    maxAgeMs: number
  ) => {
    const isProd = process.env.NODE_ENV === 'production';
    const maxAgeSec = Math.floor(maxAgeMs / 1000);
    res.setHeader('Set-Cookie', [
      `${SESSION_COOKIE}=${encodeURIComponent(rawToken)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${isProd ? '; Secure' : ''}`,
      `${CSRF_COOKIE}=${encodeURIComponent(csrfToken)}; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${isProd ? '; Secure' : ''}`,
    ]);
  };

  const clearSessionCookies = (res: Response) => {
    res.setHeader('Set-Cookie', [
      `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
      `${CSRF_COOKIE}=; SameSite=Lax; Path=/; Max-Age=0`,
    ]);
  };

  // ==========================================================================
  // HEALTH & ARCHITECTURE STATUS
  // ==========================================================================
  app.get('/api/health', (_req, res) => {
    apiSuccess(res, {
      status: 'ok',
      phase: 'Phase 03 · Master Settings & Global Configuration',
      mysqlConfigured: Boolean(process.env.DB_HOST && process.env.DB_DATABASE),
      smsEmailConfigured: isSmsOrEmailConfigured(),
      maintenanceMode: phase03Store.maintenanceSettings.maintenanceMode,
      lastHealthCheckAt: phase03Store.maintenanceSettings.lastHealthCheckAt,
    });
  });

  // ==========================================================================
  // AUTHENTICATION, CAPTCHA & OTP ROUTES
  // ==========================================================================
  app.get('/api/auth/captcha', authRateLimiter, (_req, res) => {
    const challenge = generateCaptchaChallenge();
    store.captchaChallenges.set(challenge.id, {
      id: challenge.id,
      answerHash: challenge.answerHash,
      expiresAt: Date.now() + 5 * 60_000,
    });
    apiSuccess(res, {
      challengeId: challenge.id,
      svg: challenge.svg,
      questionHint: challenge.questionHint,
    });
  });

  app.post('/api/auth/login', authRateLimiter, (req, res) => {
    const { userId, password, captchaId, captchaAnswer, rememberMe, otpChannel } = req.body ?? {};
    const errors: Record<string, string[]> = {};

    if (!userId || typeof userId !== 'string') {
      errors.userId = ['User ID is required.'];
    }
    if (!password || typeof password !== 'string') {
      errors.password = ['Password is required.'];
    }
    if (!captchaId || !captchaAnswer) {
      errors.captcha = ['CAPTCHA verification is required.'];
    }
    if (Object.keys(errors).length > 0) {
      return apiError(res, 'Validation failed.', 422, errors);
    }

    const selectedChannel = (
      ['EMAIL', 'SMS', 'WHATSAPP'].includes(String(otpChannel || '').toUpperCase())
        ? String(otpChannel).toUpperCase()
        : 'SMS'
    ) as OtpChannel;
    const devMeta = parsePrivacyDeviceMetadata(
      req.headers['user-agent'],
      req.headers['x-device-name'] as string | undefined
    );

    // Server-side CAPTCHA check
    const captchaRecord = store.captchaChallenges.get(String(captchaId));
    store.captchaChallenges.delete(String(captchaId)); // Single-use
    if (
      !captchaRecord ||
      captchaRecord.expiresAt < Date.now() ||
      hmacOtp(String(captchaAnswer).trim().toUpperCase(), captchaRecord.id) !==
        captchaRecord.answerHash
    ) {
      store.addSecurityLog({
        actorUserId: sanitizeText(String(userId)),
        eventType: 'LOGIN_FAILED',
        result: 'FAILURE',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: 'Login rejected due to invalid or expired CAPTCHA.',
      });
      return apiError(res, 'Invalid or expired CAPTCHA verification code.', 422, {
        captcha: ['Verification code did not match. Please try a new code.'],
      });
    }

    const user = store.findUserByUserId(String(userId));
    if (!user) {
      store.addSecurityLog({
        actorUserId: sanitizeText(String(userId)),
        eventType: 'LOGIN_FAILED',
        result: 'FAILURE',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: 'Failed login attempt for unknown User ID.',
      });
      return apiError(res, 'Invalid User ID or password.', 401);
    }

    // Check Account Lock
    if (user.lockedUntil && user.lockedUntil > Date.now()) {
      const remainingMin = Math.ceil((user.lockedUntil - Date.now()) / 60_000);
      store.addSecurityLog({
        actorUserId: user.userId,
        eventType: 'LOGIN_FAILED',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked login attempt while account locked (${remainingMin}m remaining).`,
      });
      return apiError(
        res,
        `Account is temporarily locked due to failed login attempts. Try again in ${remainingMin} minute(s) or reset password.`,
        423
      );
    }

    if (phase03Store.maintenanceSettings.maintenanceMode && user.role !== 'ADMIN') {
      return apiError(
        res,
        phase03Store.maintenanceSettings.maintenanceMessage ||
          'System is in Maintenance Mode. Only Admin sign-in is permitted.',
        503
      );
    }

    if (user.status !== 'ACTIVE') {
      store.addSecurityLog({
        actorUserId: user.userId,
        eventType: 'LOGIN_FAILED',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked login attempt for account status: ${user.status}.`,
      });
      return apiError(
        res,
        `Account is currently ${user.status}. Contact an Administrator.`,
        403
      );
    }

    // Verify Password Hash (never plaintext)
    if (!verifyPassword(String(password), user.passwordHash)) {
      user.failedLoginAttempts += 1;
      const shouldLock = user.failedLoginAttempts >= store.maxFailedAttempts;
      if (shouldLock) {
        user.lockedUntil = Date.now() + store.lockDurationMs;
        store.addSecurityLog({
          actorUserId: user.userId,
          eventType: 'ACCOUNT_LOCKED',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Account automatically locked after ${user.failedLoginAttempts} consecutive failed attempts.`,
        });
        phase08Store.raiseSecurityAlert({
          category: 'ACCOUNT_LOCKOUT',
          severity: 'HIGH',
          title: `Account Locked: ${user.userId}`,
          description: `Account ${user.userId} locked automatically after ${user.failedLoginAttempts} failed logins from ${getClientIp(req)}.`,
          relatedUserId: user.userId,
        });
      } else {
        store.addSecurityLog({
          actorUserId: user.userId,
          eventType: 'LOGIN_FAILED',
          result: 'FAILURE',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Invalid password attempt (${user.failedLoginAttempts}/${store.maxFailedAttempts}).`,
        });
        if (user.failedLoginAttempts >= 3) {
          phase08Store.raiseSecurityAlert({
            category: 'MULTIPLE_FAILED_LOGINS',
            severity: 'MEDIUM',
            title: `Multiple Failed Logins (${user.failedLoginAttempts}): ${user.userId}`,
            description: `${user.failedLoginAttempts} failed password attempts detected for ${user.userId} (${getClientIp(req)}).`,
            relatedUserId: user.userId,
          });
        }
      }

      const attemptsLeft = Math.max(0, store.maxFailedAttempts - user.failedLoginAttempts);
      return apiError(
        res,
        shouldLock
          ? 'Account locked after maximum failed login attempts.'
          : `Invalid User ID or password. ${attemptsLeft} attempt(s) remaining before lock.`,
        shouldLock ? 423 : 401
      );
    }

    // Password valid -> Reset failed attempts & issue 2FA Login OTP Challenge
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;

    const challengeId = generateToken(16);
    const otp = generateNumericOtp(6);
    const now = Date.now();
    const channelStatus = phase08Store.isOtpChannelConfigured(selectedChannel);
    const targetAddr = selectedChannel === 'EMAIL' ? user.email || user.mobile : user.mobile;

    store.otpChallenges.set(challengeId, {
      id: challengeId,
      target: targetAddr,
      purpose: 'LOGIN_OTP',
      channel: selectedChannel,
      otpHash: hmacOtp(otp, challengeId),
      attempts: 0,
      maxAttempts: 5,
      resendAvailableAt: now + store.otpResendCooldownMs,
      expiresAt: now + store.otpTtlMs,
      verified: false,
      userId: user.userId,
      rememberMe: Boolean(rememberMe),
    });

    phase08Store.recordOtpLog({
      challengeId,
      userId: user.userId,
      purpose: 'LOGIN_OTP',
      channel: selectedChannel,
      maskedTarget: targetAddr.replace(/.(?=.{4})/g, '*'),
      providerConfigured: channelStatus.configured,
      deliveryStatus: channelStatus.configured ? 'DELIVERED' : 'NOT_CONFIGURED',
      deliveryDetail: channelStatus.detail,
      attemptsUsed: 0,
      outcome: 'PENDING',
      ipAddress: getClientIp(req),
      deviceId: devMeta.deviceId,
      verifiedAt: null,
    });

    // Security log NEVER records the OTP value
    store.addSecurityLog({
      actorUserId: user.userId,
      eventType: 'OTP_SENT',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Login verification OTP challenge issued via ${selectedChannel}.`,
    });

    const configured = channelStatus.configured || isSmsOrEmailConfigured();
    return apiSuccess(
      res,
      {
        otpRequired: true,
        challengeId,
        channel: selectedChannel,
        deliveryStatus: channelStatus.configured ? 'DELIVERED' : 'NOT_CONFIGURED',
        deliveryDetail: channelStatus.detail,
        userId: user.userId,
        maskedMobile: user.mobile.replace(/.(?=.{4})/g, '*'),
        maskedEmail: user.email ? user.email.replace(/(?<=.{2}).(?=[^@]*@)/g, '*') : '',
        expiresInSeconds: Math.floor(store.otpTtlMs / 1000),
        resendCooldownSeconds: Math.floor(store.otpResendCooldownMs / 1000),
        providerConfigured: configured,
        totpEnabled: Boolean(user.totpEnabled),
        ...(configured ? {} : { sandboxOtpPreview: otp }),
      },
      'Credentials verified. Complete OTP or Google Authenticator verification to start session.'
    );
  });

  app.post('/api/auth/verify-otp', authRateLimiter, (req, res) => {
    const { challengeId, otp, method } = req.body ?? {};
    const verificationMethod = String(method || 'SMS').toUpperCase() === 'TOTP' ? 'TOTP' : 'SMS';
    if (!challengeId || !otp) {
      return apiError(res, 'Challenge ID and verification code are required.', 422);
    }

    const challenge = store.otpChallenges.get(String(challengeId));
    if (!challenge) {
      return apiError(res, 'OTP challenge not found or expired.', 400);
    }

    const otpLog = phase08Store.otpLogs.find((l) => l.challengeId === challenge.id);

    if (challenge.verified) {
      return apiError(res, 'OTP challenge already used.', 400);
    }

    if (challenge.expiresAt <= Date.now()) {
      if (otpLog) otpLog.outcome = 'EXPIRED';
      return apiError(res, 'Verification challenge has expired. Request a new code.', 400);
    }

    if (challenge.attempts >= challenge.maxAttempts) {
      if (otpLog) otpLog.outcome = 'LOCKED';
      return apiError(res, 'Maximum verification attempts exceeded.', 429);
    }

    challenge.attempts += 1;
    if (otpLog) otpLog.attemptsUsed = challenge.attempts;

    let codeValid = false;
    if (verificationMethod === 'TOTP') {
      const challengeUser = challenge.userId ? store.findUserByUserId(challenge.userId) : undefined;
      if (!challengeUser?.totpEnabled || !challengeUser.totpSecretEncrypted) {
        return apiError(
          res,
          'Google Authenticator (TOTP) is not linked to this account. Use SMS OTP or configure TOTP in Security Settings.',
          400
        );
      }
      try {
        const base32Secret = decryptSensitiveField(challengeUser.totpSecretEncrypted);
        const totp = new OTPAuth.TOTP({
          issuer: 'MUN COMPUTER',
          label: challengeUser.email || challengeUser.userId,
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          secret: OTPAuth.Secret.fromBase32(base32Secret),
        });
        codeValid = totp.validate({ token: String(otp).trim(), window: 1 }) !== null;
      } catch {
        codeValid = false;
      }
    } else {
      const expected = hmacOtp(String(otp).trim(), challenge.id);
      codeValid = expected === challenge.otpHash;
    }

    if (!codeValid) {
      if (otpLog) {
        otpLog.outcome = challenge.attempts >= challenge.maxAttempts ? 'LOCKED' : 'FAILED';
      }
      store.addSecurityLog({
        actorUserId: challenge.userId ?? challenge.target,
        eventType: 'OTP_FAILED',
        result: 'FAILURE',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `${verificationMethod} verification failed (${challenge.attempts}/${challenge.maxAttempts}).`,
      });
      return apiError(
        res,
        `Invalid ${verificationMethod === 'TOTP' ? 'Google Authenticator code' : 'OTP'}. ${challenge.maxAttempts - challenge.attempts} attempt(s) remaining.`,
        401
      );
    }

    challenge.verified = true;
    if (otpLog) {
      otpLog.outcome = 'VERIFIED';
      otpLog.verifiedAt = new Date().toISOString();
    }

    if (challenge.purpose === 'MOBILE_VERIFICATION') {
      return apiSuccess(
        res,
        {
          mobileVerified: true,
          verificationToken: challenge.id,
        },
        'Mobile number verified via OTP.'
      );
    }

    if (challenge.purpose === 'SENSITIVE_ACTION') {
      store.otpChallenges.delete(challenge.id);
      return apiSuccess(res, { verified: true, purpose: 'SENSITIVE_ACTION' }, 'Sensitive action step-up OTP verified.');
    }

    if (challenge.purpose === 'LOGIN_OTP' && challenge.userId) {
      const user = store.findUserByUserId(challenge.userId);
      if (!user || user.status !== 'ACTIVE') {
        return apiError(res, 'User account is unavailable.', 403);
      }

      const devMeta = parsePrivacyDeviceMetadata(
        req.headers['user-agent'],
        req.headers['x-device-name'] as string | undefined
      );
      const { device, isNewDevice } = phase08Store.registerOrTouchDevice({
        userId: user.userId,
        deviceId: devMeta.deviceId,
        deviceName: devMeta.deviceName,
        browserInfo: devMeta.browserInfo,
        osInfo: devMeta.osInfo,
        ipAddress: getClientIp(req),
        trustIfFirst: true,
      });

      if (device.verificationStatus === 'REVOKED' || device.verificationStatus === 'SUSPICIOUS') {
        return apiError(
          res,
          `Device ${device.deviceId} is marked ${device.verificationStatus}. Contact Admin to restore device access.`,
          403
        );
      }

      // Enforce concurrent session limit cleanly (evict oldest session beyond limit)
      const activeUserSessions = Array.from(store.sessions.values())
        .filter((s) => s.userId === user.userId && s.status === 'ACTIVE' && s.expiresAt > Date.now())
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      while (activeUserSessions.length >= phase08Store.settings.maxConcurrentSessions) {
        const oldest = activeUserSessions.shift();
        if (oldest) oldest.status = 'REVOKED';
      }

      const rawToken = generateToken(32);
      const csrfToken = generateToken(24);
      const ttl = challenge.rememberMe
        ? Math.min(store.rememberMeTtlMs, MAX_REMEMBER_ME_MS)
        : store.sessionTtlMs;
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const expiresAt = nowMs + ttl;
      const session: ServerSession = {
        id: generateToken(8),
        tokenHash: sha256(rawToken),
        userId: user.userId,
        role: user.role,
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        deviceId: device.deviceId,
        lastActiveAt: nowIso,
        rememberMe: Boolean(challenge.rememberMe),
        maxAllowedExpiresAt: expiresAt,
        reauthenticatedUntil: null,
        status: 'ACTIVE',
        createdAt: nowIso,
        expiresAt,
      };
      store.sessions.set(session.tokenHash, session);
      store.otpChallenges.delete(challenge.id);

      setSessionCookies(res, rawToken, csrfToken, ttl);

      store.addSecurityLog({
        actorUserId: user.userId,
        eventType: 'LOGIN_SUCCESS',
        result: 'SUCCESS',
        ipAddress: session.ipAddress,
        deviceInfo: session.deviceInfo,
        summary: `Authenticated ${user.role} session started (${session.id}, ${session.rememberMe ? '240-min Remember Me' : '60-min standard'}) on ${device.deviceId}.`,
      });
      phase08Store.recordBeforeAfterAudit({
        userId: user.userId,
        userRole: user.role,
        actionType: 'LOGIN_SESSION_STARTED',
        module: 'authentication',
        recordId: session.id,
        beforeValues: null,
        afterValues: {
          sessionId: session.id,
          deviceId: device.deviceId,
          deviceStatus: device.verificationStatus,
          channel: challenge.channel || 'SMS',
          rememberMe: session.rememberMe,
          rememberMeMaxMinutes: 240,
        },
        ipAddress: session.ipAddress,
        deviceInfo: session.deviceInfo,
        actionResult: 'SUCCESS',
      });

      return apiSuccess(
        res,
        {
          user: store.sanitizePublicUser(user, user.role),
          permissions: store.getEffectivePermissions(user),
          csrfToken,
          passwordExpired: phase08Store.isPasswordExpired(user),
          device: {
            deviceId: device.deviceId,
            deviceName: device.deviceName,
            verificationStatus: device.verificationStatus,
            isNewDevice,
          },
          session: {
            id: session.id,
            createdAt: session.createdAt,
            expiresAt: new Date(session.expiresAt).toISOString(),
            maxAllowedExpiresAt: new Date(session.maxAllowedExpiresAt).toISOString(),
            rememberMe: session.rememberMe,
            rememberMeMaxMinutes: 240,
            reauthenticated: false,
          },
        },
        'Login OTP verified. Session active.'
      );
    }

    return apiSuccess(res, { verified: true }, 'OTP verified.');
  });

  app.post('/api/auth/resend-otp', authRateLimiter, (req, res) => {
    const { challengeId, channel } = req.body ?? {};
    const existing = store.otpChallenges.get(String(challengeId ?? ''));
    if (!existing) {
      return apiError(res, 'OTP challenge not found.', 404);
    }
    if (existing.resendAvailableAt > Date.now()) {
      const waitSec = Math.ceil((existing.resendAvailableAt - Date.now()) / 1000);
      return apiError(res, `Please wait ${waitSec}s before requesting another OTP.`, 429);
    }

    const windowKey = existing.userId || existing.target;
    const oneHourAgo = Date.now() - 3600_000;
    const recentSends = (phase08Store.otpResendWindows.get(windowKey) ?? []).filter((ts) => ts > oneHourAgo);
    if (recentSends.length >= phase08Store.settings.otpMaxResendsPerHour) {
      return apiError(res, 'Hourly OTP resend limit reached. Try again later.', 429);
    }
    recentSends.push(Date.now());
    phase08Store.otpResendWindows.set(windowKey, recentSends);

    const activeChannel = (
      ['EMAIL', 'SMS', 'WHATSAPP'].includes(String(channel || '').toUpperCase())
        ? String(channel).toUpperCase()
        : existing.channel || 'SMS'
    ) as OtpChannel;
    existing.channel = activeChannel;

    const newOtp = generateNumericOtp(6);
    const now = Date.now();
    existing.otpHash = hmacOtp(newOtp, existing.id);
    existing.attempts = 0;
    existing.expiresAt = now + store.otpTtlMs;
    existing.resendAvailableAt = now + store.otpResendCooldownMs;

    const chStatus = phase08Store.isOtpChannelConfigured(activeChannel);
    const devMeta = parsePrivacyDeviceMetadata(
      req.headers['user-agent'],
      req.headers['x-device-name'] as string | undefined
    );
    phase08Store.recordOtpLog({
      challengeId: existing.id,
      userId: existing.userId,
      purpose: existing.purpose,
      channel: activeChannel,
      maskedTarget: existing.target.replace(/.(?=.{4})/g, '*'),
      providerConfigured: chStatus.configured,
      deliveryStatus: chStatus.configured ? 'DELIVERED' : 'NOT_CONFIGURED',
      deliveryDetail: `Resent: ${chStatus.detail}`,
      attemptsUsed: 0,
      outcome: 'PENDING',
      ipAddress: getClientIp(req),
      deviceId: devMeta.deviceId,
      verifiedAt: null,
    });

    store.addSecurityLog({
      actorUserId: existing.userId ?? existing.target,
      eventType: 'OTP_SENT',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Resent ${existing.purpose} OTP challenge via ${activeChannel}.`,
    });

    const configured = chStatus.configured || isSmsOrEmailConfigured();
    return apiSuccess(res, {
      challengeId: existing.id,
      channel: activeChannel,
      deliveryStatus: chStatus.configured ? 'DELIVERED' : 'NOT_CONFIGURED',
      deliveryDetail: chStatus.detail,
      resendCooldownSeconds: Math.floor(store.otpResendCooldownMs / 1000),
      providerConfigured: configured,
      ...(configured ? {} : { sandboxOtpPreview: newOtp }),
    }, 'New OTP dispatched.');
  });

  app.post('/api/auth/mobile-otp/send', authRateLimiter, (req, res) => {
    const { mobile } = req.body ?? {};
    if (!mobile || String(mobile).trim().length < 8) {
      return apiError(res, 'Valid mobile number is required.', 422, {
        mobile: ['Enter a valid mobile number.'],
      });
    }
    const challengeId = generateToken(16);
    const otp = generateNumericOtp(6);
    const now = Date.now();
    store.otpChallenges.set(challengeId, {
      id: challengeId,
      target: String(mobile).trim(),
      purpose: 'MOBILE_VERIFICATION',
      otpHash: hmacOtp(otp, challengeId),
      attempts: 0,
      maxAttempts: 5,
      resendAvailableAt: now + store.otpResendCooldownMs,
      expiresAt: now + store.otpTtlMs,
      verified: false,
    });

    const configured = isSmsOrEmailConfigured();
    return apiSuccess(res, {
      challengeId,
      expiresInSeconds: Math.floor(store.otpTtlMs / 1000),
      resendCooldownSeconds: Math.floor(store.otpResendCooldownMs / 1000),
      providerConfigured: configured,
      ...(configured ? {} : { sandboxOtpPreview: otp }),
    }, 'Mobile verification OTP dispatched.');
  });

  app.post('/api/auth/forgot-password', authRateLimiter, (req, res) => {
    const { userId } = req.body ?? {};
    if (!userId || typeof userId !== 'string') {
      return apiError(res, 'User ID is required.', 422, {
        userId: ['Enter your assigned MUN COMPUTER User ID.'],
      });
    }

    const user = store.findUserByUserId(userId);
    if (!user) {
      // Do not leak detailed account presence on unknown IDs, except clear demo UX feedback
      return apiError(res, 'No account matches the provided User ID.', 404);
    }

    const challengeId = generateToken(16);
    const otp = generateNumericOtp(6);
    const now = Date.now();
    store.otpChallenges.set(challengeId, {
      id: challengeId,
      target: user.mobile,
      purpose: 'PASSWORD_RESET',
      otpHash: hmacOtp(otp, challengeId),
      attempts: 0,
      maxAttempts: 5,
      resendAvailableAt: now + store.otpResendCooldownMs,
      expiresAt: now + store.otpTtlMs,
      verified: false,
      userId: user.userId,
    });

    store.addSecurityLog({
      actorUserId: user.userId,
      eventType: 'OTP_SENT',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: 'Password reset OTP challenge issued.',
    });

    const configured = isSmsOrEmailConfigured();
    return apiSuccess(res, {
      challengeId,
      userId: user.userId,
      maskedMobile: user.mobile.replace(/.(?=.{4})/g, '*'),
      expiresInSeconds: Math.floor(store.otpTtlMs / 1000),
      providerConfigured: configured,
      ...(configured ? {} : { sandboxOtpPreview: otp }),
    }, 'Password reset OTP dispatched.');
  });

  app.post('/api/auth/reset-password', authRateLimiter, (req, res) => {
    const { challengeId, otp, newPassword, confirmPassword } = req.body ?? {};
    const errors: Record<string, string[]> = {};
    if (!challengeId) errors.challengeId = ['Reset challenge is missing.'];
    if (!otp) errors.otp = ['OTP is required.'];
    const pwdErr = validateStrongPassword(newPassword);
    if (pwdErr) {
      errors.newPassword = [pwdErr];
    }
    if (newPassword !== confirmPassword) {
      errors.confirmPassword = ['Passwords do not match.'];
    }
    if (Object.keys(errors).length > 0) {
      return apiError(res, 'Validation failed.', 422, errors);
    }

    const challenge = store.otpChallenges.get(String(challengeId));
    if (
      !challenge ||
      challenge.purpose !== 'PASSWORD_RESET' ||
      challenge.expiresAt <= Date.now()
    ) {
      return apiError(res, 'Password reset OTP expired or invalid.', 400);
    }

    if (challenge.attempts >= challenge.maxAttempts) {
      return apiError(res, 'Maximum OTP attempts exceeded.', 429);
    }
    challenge.attempts += 1;

    if (hmacOtp(String(otp).trim(), challenge.id) !== challenge.otpHash) {
      return apiError(res, 'Invalid password reset OTP.', 401);
    }

    const user = challenge.userId ? store.findUserByUserId(challenge.userId) : undefined;
    if (!user) {
      return apiError(res, 'User account not found.', 404);
    }

    if (phase08Store.checkPasswordAgainstHistory(user.userId, String(newPassword))) {
      return apiError(
        res,
        `Password policy prohibits reusing any of your last ${phase08Store.settings.passwordHistoryCount} password(s).`,
        422,
        { newPassword: ['Choose a password not previously used.'] }
      );
    }

    const nextHash = hashPassword(String(newPassword));
    user.passwordHash = nextHash;
    phase08Store.pushPasswordHistory(user.userId, nextHash);
    user.passwordChangedAt = new Date().toISOString();
    user.updatedAt = user.passwordChangedAt;
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    store.otpChallenges.delete(challenge.id);

    // Revoke all existing sessions after password reset
    for (const session of store.sessions.values()) {
      if (session.userId === user.userId && session.status === 'ACTIVE') {
        session.status = 'REVOKED';
      }
    }

    store.addSecurityLog({
      actorUserId: user.userId,
      eventType: 'PASSWORD_RESET',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: 'Password reset completed via OTP; prior sessions invalidated.',
    });
    store.addPhase02Notification({
      triggerType: 'PASSWORD_CHANGED',
      recipientUserId: user.userId,
      title: 'Password Reset Completed',
      message: 'Your MUN COMPUTER password was reset and all previous active sessions were revoked.',
      severity: 'INFO',
    });
    phase08Store.recordBeforeAfterAudit({
      userId: user.userId,
      userRole: user.role,
      actionType: 'PASSWORD_RESET_COMPLETED',
      module: 'authentication',
      recordId: user.userId,
      beforeValues: null,
      afterValues: { passwordChangedAt: user.passwordChangedAt, sessionsRevoked: true },
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      actionResult: 'SUCCESS',
    });

    return apiSuccess(res, { reset: true }, 'Password has been reset. Please sign in.');
  });

  // Google Authenticator (TOTP) 2FA status & enrollment routes
  app.get('/api/auth/totp/status', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    return apiSuccess(res, {
      totpEnabled: Boolean(actor.totpEnabled),
      userId: actor.userId,
    });
  });

  app.post('/api/auth/totp/enable', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const { secret, code } = req.body ?? {};
    const cleanSecret = String(secret || '').trim().toUpperCase().replace(/\s+/g, '');
    const cleanCode = String(code || '').trim();
    if (!cleanSecret || !/^\d{6}$/.test(cleanCode)) {
      return apiError(res, 'Valid Base32 setup key and 6-digit authenticator code are required.', 422);
    }

    try {
      const totp = new OTPAuth.TOTP({
        issuer: 'MUN COMPUTER',
        label: actor.email || actor.userId,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(cleanSecret),
      });
      const delta = totp.validate({ token: cleanCode, window: 1 });
      if (delta === null) {
        return apiError(res, 'Invalid 6-digit Google Authenticator verification code.', 422);
      }

      actor.totpSecretEncrypted = encryptSensitiveField(cleanSecret);
      actor.totpEnabled = true;
      actor.updatedAt = new Date().toISOString();

      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'PROFILE_UPDATED',
        result: 'SUCCESS',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Google Authenticator (TOTP 2FA) enabled for ${actor.userId}.`,
      });

      return apiSuccess(res, { totpEnabled: true }, 'Google Authenticator (TOTP) enabled.');
    } catch {
      return apiError(res, 'Invalid Base32 TOTP secret.', 422);
    }
  });

  app.post('/api/auth/totp/verify-code', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const { code } = req.body ?? {};
    const cleanCode = String(code || '').trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return apiError(res, 'Enter a valid 6-digit Google Authenticator code.', 422);
    }
    if (!actor.totpEnabled || !actor.totpSecretEncrypted) {
      return apiError(res, 'Google Authenticator is not yet linked to this account.', 400);
    }

    try {
      const base32Secret = decryptSensitiveField(actor.totpSecretEncrypted);
      const totp = new OTPAuth.TOTP({
        issuer: 'MUN COMPUTER',
        label: actor.email || actor.userId,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(base32Secret),
      });
      const delta = totp.validate({ token: cleanCode, window: 1 });
      if (delta === null) {
        return apiError(res, 'Invalid 6-digit Google Authenticator code.', 401);
      }
      return apiSuccess(res, { verified: true }, 'Google Authenticator code verified.');
    } catch {
      return apiError(res, 'Unable to verify Google Authenticator code.', 500);
    }
  });

  app.post('/api/auth/totp/disable', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    actor.totpSecretEncrypted = undefined;
    actor.totpEnabled = false;
    actor.updatedAt = new Date().toISOString();
    store.addSecurityLog({
      actorUserId: actor.userId,
      eventType: 'PROFILE_UPDATED',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Google Authenticator (TOTP 2FA) disabled for ${actor.userId}.`,
    });
    return apiSuccess(res, { totpEnabled: false }, 'Google Authenticator disabled.');
  });

  // Sensitive action re-authentication with session token rotation (never exceeds 240-min cap)
  app.post('/api/auth/reauthenticate', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const currentSession = req.authSession!;
    const { password } = req.body ?? {};

    if (!password || typeof password !== 'string' || !verifyPassword(password, actor.passwordHash)) {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'REAUTH_FAILED',
        result: 'FAILURE',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Sensitive-operation re-authentication failed for ${actor.userId}.`,
      });
      return apiError(res, 'Re-authentication failed: invalid password.', 401);
    }

    const nowMs = Date.now();
    const remainingTtlMs = Math.max(1000, currentSession.maxAllowedExpiresAt - nowMs);
    const rotatedRawToken = generateToken(32);
    const rotatedCsrf = generateToken(24);

    // Revoke previous token hash and issue rotated token preserving maxAllowedExpiresAt
    store.sessions.delete(currentSession.tokenHash);
    const rotatedSession: ServerSession = {
      ...currentSession,
      id: generateToken(8),
      tokenHash: sha256(rotatedRawToken),
      rotatedFromSessionId: currentSession.id,
      lastActiveAt: new Date(nowMs).toISOString(),
      reauthenticatedUntil: nowMs + 10 * 60_000,
    };
    store.sessions.set(rotatedSession.tokenHash, rotatedSession);
    setSessionCookies(res, rotatedRawToken, rotatedCsrf, remainingTtlMs);

    store.addSecurityLog({
      actorUserId: actor.userId,
      eventType: 'REAUTH_SUCCESS',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Re-authenticated ${actor.userId} and rotated session token (${currentSession.id} -> ${rotatedSession.id}).`,
    });

    return apiSuccess(res, {
      reauthenticated: true,
      reauthenticatedUntil: new Date(rotatedSession.reauthenticatedUntil!).toISOString(),
      csrfToken: rotatedCsrf,
      session: {
        id: rotatedSession.id,
        createdAt: rotatedSession.createdAt,
        expiresAt: new Date(rotatedSession.expiresAt).toISOString(),
        maxAllowedExpiresAt: new Date(rotatedSession.maxAllowedExpiresAt).toISOString(),
        rememberMe: rotatedSession.rememberMe,
      },
    }, 'Re-authentication confirmed and session token rotated.');
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthedRequest, res) => {
    const session = req.authSession!;
    const user = req.authUser!;
    session.status = 'REVOKED';
    clearSessionCookies(res);

    store.addSecurityLog({
      actorUserId: user.userId,
      eventType: 'LOGOUT',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `User ${user.userId} logged out and invalidated session ${session.id}.`,
    });

    return apiSuccess(res, { loggedOut: true }, 'Session invalidated.');
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    const user = req.authUser!;
    const session = req.authSession!;
    const cookies = parseCookies(req.headers.cookie);
    return apiSuccess(res, {
      user: store.sanitizePublicUser(user, user.role),
      permissions: store.getEffectivePermissions(user),
      csrfToken: cookies[CSRF_COOKIE] || null,
      session: {
        id: session.id,
        expiresAt: new Date(session.expiresAt).toISOString(),
        maxAllowedExpiresAt: new Date(session.maxAllowedExpiresAt).toISOString(),
        rememberMe: session.rememberMe,
        rememberMeMaxMinutes: 240,
        reauthenticated: Boolean(session.reauthenticatedUntil && session.reauthenticatedUntil > Date.now()),
      },
    });
  });

  // ==========================================================================
  // USER MANAGEMENT ROUTES
  // ==========================================================================
  app.get(
    '/api/users',
    requireAuth,
    requirePermission('users', 'VIEW'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const visible = store.users.filter((u) =>
        actor.role === 'MANAGER' ? u.role !== 'ADMIN' : true
      );
      return apiSuccess(
        res,
        visible.map((u) => store.sanitizePublicUser(u, actor.role))
      );
    }
  );

  app.get('/api/users/id-prefix-preview', requireAuth, (req: AuthedRequest, res) => {
    const roleParam = String(req.query.role ?? 'STAFF').toUpperCase() as RoleName;
    if (!['ADMIN', 'MANAGER', 'STAFF', 'AUDITOR', 'CUSTOMER'].includes(roleParam)) {
      return apiError(res, 'Invalid role parameter.', 400);
    }
    const prefix = store.sequenceService.getPrefixPreview(roleParam);
    return apiSuccess(res, {
      role: roleParam,
      prefix,
      format: 'MCYYFFMMSSSS',
      example: `${prefix}XXXX`,
      nextExample: `${prefix}0001`,
    });
  });

  app.get('/api/users/id-generation-history', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (!['ADMIN', 'MANAGER', 'AUDITOR'].includes(actor.role)) {
      return apiError(res, 'Forbidden: cannot view User ID generation ledger.', 403);
    }
    return apiSuccess(res, store.sequenceService.getGenerationHistory());
  });

  app.post(
    '/api/users',
    requireAuth,
    requirePermission('users', 'ADD'),
    async (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const {
        fullName,
        role,
        mobile,
        email,
        address,
        aadhaarNumber,
        aadhaarConsent,
        password,
        confirmPassword,
        branch,
        designation,
        departmentCode,
        joiningDate,
        emergencyContact,
        profilePhotoUrl,
      } = req.body ?? {};

      const targetRole = String(role ?? 'STAFF').toUpperCase() as RoleName;
      if (!['ADMIN', 'MANAGER', 'STAFF', 'AUDITOR', 'CUSTOMER'].includes(targetRole)) {
        return apiError(res, 'Invalid target role.', 422);
      }

      // Role creation permission matrix per Part 03
      if (actor.role === 'ADMIN') {
        // ADMIN can create ADMIN, MANAGER, STAFF, EMPLOYEE, AUDITOR
      } else if (actor.role === 'MANAGER') {
        if (!['STAFF', 'EMPLOYEE'].includes(targetRole)) {
          store.addSecurityLog({
            actorUserId: actor.userId,
            eventType: 'UNAUTHORIZED_ACCESS',
            result: 'BLOCKED',
            ipAddress: getClientIp(req),
            deviceInfo: getDeviceInfo(req),
            summary: `Manager ${actor.userId} blocked from creating ${targetRole} account.`,
          });
          return apiError(res, 'Managers can only create STAFF and EMPLOYEE accounts.', 403);
        }
      } else if (actor.role === 'STAFF') {
        if (targetRole !== 'EMPLOYEE') {
          store.addSecurityLog({
            actorUserId: actor.userId,
            eventType: 'UNAUTHORIZED_ACCESS',
            result: 'BLOCKED',
            ipAddress: getClientIp(req),
            deviceInfo: getDeviceInfo(req),
            summary: `Staff ${actor.userId} blocked from creating ${targetRole} account.`,
          });
          return apiError(res, 'Staff can only create EMPLOYEE accounts.', 403);
        }
      } else {
        return apiError(res, 'You do not have permission to create user accounts.', 403);
      }

      const errors: Record<string, string[]> = {};
      if (!fullName || String(fullName).trim().length < 2) {
        errors.fullName = ['Full name must be at least 2 characters.'];
      }
      if (!mobile || String(mobile).trim().length < 8) {
        errors.mobile = ['Valid mobile number is required.'];
      }
      if (!address || String(address).trim().length < 4) {
        errors.address = ['Address is required.'];
      }
      const pwdErr = validateStrongPassword(password);
      if (pwdErr) {
        errors.password = [pwdErr];
      }
      if (password !== confirmPassword) {
        errors.confirmPassword = ['Passwords do not match.'];
      }
      if (aadhaarNumber) {
        const cleanedAadhaar = String(aadhaarNumber).replace(/\s|-/g, '');
        if (!/^\d{12}$/.test(cleanedAadhaar)) {
          errors.aadhaarNumber = ['Aadhaar must be 12 digits when provided.'];
        }
        if (!aadhaarConsent) {
          errors.aadhaarConsent = [
            'Explicit informed consent is required before encrypting Aadhaar.',
          ];
        }
      }
      if (Object.keys(errors).length > 0) {
        return apiError(res, 'Validation failed.', 422, errors);
      }

      // Duplicate mobile check
      if (store.users.some((u) => u.mobile === String(mobile).trim())) {
        return apiError(res, 'Mobile number is already registered.', 409);
      }

      let aadhaarEncrypted: string | undefined;
      let aadhaarLast4: string | undefined;
      let aadhaarConsentAt: string | undefined;
      if (aadhaarNumber) {
        const cleaned = String(aadhaarNumber).replace(/\s|-/g, '');
        aadhaarEncrypted = encryptSensitiveField(cleaned);
        aadhaarLast4 = cleaned.slice(-4);
        aadhaarConsentAt = new Date().toISOString();
      }

      const resolvedDept = departmentCode ? sanitizeText(String(departmentCode)).toUpperCase() : 'DEPT-CSC';
      const resolvedDesignation = designation ? sanitizeText(String(designation)) : `${targetRole} Associate`;
      const resolvedJoinDate = joiningDate ? sanitizeText(String(joiningDate)) : new Date().toISOString().slice(0, 10);

      // Manager registrations enter approval workflow for Staff; Admin creates directly
      if (actor.role === 'MANAGER') {
        const now = new Date().toISOString();
        const requestRecord = {
          id: store.registrationRequests.length + 1,
          requestId: store.nextRequestCode(),
          applicantName: sanitizeText(String(fullName)),
          requestedRole: 'STAFF' as RoleName,
          mobile: sanitizeText(String(mobile)),
          email: email ? sanitizeText(String(email)) : undefined,
          address: sanitizeText(String(address)),
          designation: resolvedDesignation,
          departmentCode: resolvedDept,
          joiningDate: resolvedJoinDate,
          aadhaarEncrypted,
          aadhaarLast4,
          aadhaarConsentAt,
          passwordHash: hashPassword(String(password)),
          mobileVerified: true,
          submittedBy: actor.userId,
          status: 'PENDING' as const,
          createdAt: now,
          updatedAt: now,
        };
        store.registrationRequests.unshift(requestRecord);

        store.addAuditLog({
          actorUserId: actor.userId,
          action: 'SUBMIT_STAFF_REGISTRATION',
          targetType: 'registration_request',
          targetId: requestRecord.requestId,
          details: `Manager submitted STAFF registration request for ${requestRecord.applicantName}.`,
          ipAddress: getClientIp(req),
        });
        store.addPhase02Notification({
          triggerType: 'STAFF_REGISTRATION_PENDING',
          recipientUserId: 'MC2627110001',
          title: `Staff Registration Pending: ${requestRecord.requestId}`,
          message: `Manager ${actor.userId} submitted STAFF onboarding request for ${requestRecord.applicantName}.`,
          severity: 'INFO',
        });

        return apiSuccess(
          res,
          { registrationRequest: requestRecord, requiresApproval: true },
          'Staff registration submitted to Approval Management workflow.',
          201
        );
      }

      // Admin direct creation -> atomic User ID allocation (MCYYFFMMSSSS)
      const generatedUserId = await store.sequenceService.allocateNext(
        targetRole,
        undefined,
        undefined,
        {
          actorUserId: actor.userId,
          departmentCode: resolvedDept,
        }
      );
      const now = new Date().toISOString();
      const newUser: ServerUser = {
        id: store.users.length + 1,
        userId: generatedUserId,
        isMasterAdmin: false,
        fullName: sanitizeText(String(fullName)),
        role: targetRole,
        mobile: sanitizeText(String(mobile)),
        email: email ? sanitizeText(String(email)) : undefined,
        address: sanitizeText(String(address)),
        designation: resolvedDesignation,
        departmentCode: resolvedDept,
        joiningDate: resolvedJoinDate,
        emergencyContact: emergencyContact ? sanitizeText(String(emergencyContact)) : undefined,
        profilePhotoUrl: profilePhotoUrl ? sanitizeText(String(profilePhotoUrl)) : undefined,
        aadhaarEncrypted,
        aadhaarLast4,
        aadhaarConsentAt,
        passwordHash: hashPassword(String(password)),
        passwordAlgo: 'scrypt-v1',
        branch: branch ? sanitizeText(String(branch)) : 'Main Service Center',
        status: 'ACTIVE',
        mobileVerified: true,
        emailVerified: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdBy: actor.userId,
        createdAt: now,
        updatedAt: now,
        passwordChangedAt: now,
        customPermissions: {},
      };
      store.users.unshift(newUser);
      phase08Store.pushPasswordHistory(newUser.userId, newUser.passwordHash);

      store.addAuditLog({
        actorUserId: actor.userId,
        action: 'CREATE_USER',
        targetType: 'user',
        targetId: newUser.userId,
        details: `Provisioned ${newUser.role} account ${newUser.userId} (${newUser.fullName}, ${resolvedDept}).`,
        ipAddress: getClientIp(req),
      });
      store.addSecurityLog({
        actorUserId: actor.userId,
        targetUserId: newUser.userId,
        eventType: 'USER_CREATED',
        result: 'SUCCESS',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Admin created ${newUser.role} account ${newUser.userId} in ${resolvedDept}.`,
      });
      store.addPhase02Notification({
        triggerType: 'STAFF_ACCOUNT_CREATED',
        recipientUserId: newUser.userId,
        title: `Account Provisioned: ${newUser.userId}`,
        message: `Your ${newUser.role} account (${newUser.userId}) is active under ${resolvedDept}.`,
        severity: 'INFO',
      });

      return apiSuccess(
        res,
        { user: store.sanitizePublicUser(newUser, actor.role), requiresApproval: false },
        `User ${newUser.userId} created.`,
        201
      );
    }
  );

  app.get('/api/users/:id', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const target = store.findUserByUserId(req.params.id) ?? store.findUserByNumericId(Number(req.params.id));
    if (!target) {
      return apiError(res, 'User not found.', 404);
    }
    if (actor.userId !== target.userId && !store.hasPermission(actor, 'users', 'VIEW')) {
      return apiError(res, 'Forbidden: cannot inspect another user profile.', 403);
    }
    if (actor.role === 'MANAGER' && target.role === 'ADMIN') {
      return apiError(res, 'Forbidden: Managers cannot inspect Admin accounts.', 403);
    }
    return apiSuccess(res, store.sanitizePublicUser(target, actor.role));
  });

  app.put('/api/users/:id', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const target = store.findUserByUserId(req.params.id) ?? store.findUserByNumericId(Number(req.params.id));
    if (!target) return apiError(res, 'User not found.', 404);

    const isSelf = actor.userId === target.userId;
    if (!isSelf && !store.hasPermission(actor, 'users', 'EDIT')) {
      return apiError(res, 'Forbidden: insufficient permissions to edit user.', 403);
    }
    if (actor.role === 'MANAGER' && target.role === 'ADMIN') {
      return apiError(res, 'Forbidden: Managers cannot modify Admin accounts.', 403);
    }

    const {
      fullName,
      email,
      address,
      branch,
      designation,
      departmentCode,
      joiningDate,
      emergencyContact,
      profilePhotoUrl,
    } = req.body ?? {};
    // User IDs and Master Admin roles are immutable after creation!
    if (fullName && String(fullName).trim().length >= 2) {
      target.fullName = sanitizeText(String(fullName));
    }
    if (typeof email === 'string') {
      target.email = sanitizeText(email) || undefined;
    }
    if (typeof address === 'string' && address.trim().length >= 4) {
      target.address = sanitizeText(address);
    }
    if (typeof branch === 'string' && !isSelf) {
      target.branch = sanitizeText(branch);
    }
    if (typeof designation === 'string' && !isSelf) {
      target.designation = sanitizeText(designation);
    }
    if (typeof departmentCode === 'string' && !isSelf && actor.role === 'ADMIN') {
      target.departmentCode = sanitizeText(departmentCode).toUpperCase();
    }
    if (typeof joiningDate === 'string' && !isSelf) {
      target.joiningDate = sanitizeText(joiningDate);
    }
    if (typeof emergencyContact === 'string') {
      target.emergencyContact = sanitizeText(emergencyContact) || undefined;
    }
    if (typeof profilePhotoUrl === 'string') {
      target.profilePhotoUrl = sanitizeText(profilePhotoUrl) || undefined;
    }
    target.updatedAt = new Date().toISOString();

    store.addAuditLog({
      actorUserId: actor.userId,
      action: 'UPDATE_USER_PROFILE',
      targetType: 'user',
      targetId: target.userId,
      details: `Updated profile details for ${target.userId}.`,
      ipAddress: getClientIp(req),
    });
    store.addSecurityLog({
      actorUserId: actor.userId,
      targetUserId: target.userId,
      eventType: 'PROFILE_UPDATED',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Profile details updated for ${target.userId}.`,
    });

    return apiSuccess(res, store.sanitizePublicUser(target, actor.role), 'Profile updated.');
  });

  app.post('/api/users/:id/change-password', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const target = store.findUserByUserId(req.params.id);
    if (!target || target.userId !== actor.userId) {
      return apiError(res, 'You may only change your own password here.', 403);
    }

    const { currentPassword, newPassword, confirmPassword } = req.body ?? {};
    if (!currentPassword || !verifyPassword(String(currentPassword), target.passwordHash)) {
      return apiError(res, 'Current password is incorrect.', 401);
    }
    const pwdErr = validateStrongPassword(newPassword);
    if (pwdErr) {
      return apiError(res, pwdErr, 422);
    }
    if (newPassword !== confirmPassword) {
      return apiError(res, 'New password and confirmation do not match.', 422);
    }
    if (phase08Store.checkPasswordAgainstHistory(target.userId, String(newPassword))) {
      return apiError(
        res,
        `Password policy prohibits reusing any of your last ${phase08Store.settings.passwordHistoryCount} password(s).`,
        422
      );
    }

    const nextHash = hashPassword(String(newPassword));
    target.passwordHash = nextHash;
    phase08Store.pushPasswordHistory(target.userId, nextHash);
    target.passwordChangedAt = new Date().toISOString();
    target.updatedAt = target.passwordChangedAt;

    // Revoke other active sessions after password update
    for (const session of store.sessions.values()) {
      if (session.userId === target.userId && session.id !== req.authSession!.id && session.status === 'ACTIVE') {
        session.status = 'REVOKED';
      }
    }

    store.addSecurityLog({
      actorUserId: actor.userId,
      targetUserId: target.userId,
      eventType: 'PASSWORD_CHANGED',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: 'User updated account password; other active sessions revoked.',
    });
    store.addPhase02Notification({
      triggerType: 'PASSWORD_CHANGED',
      recipientUserId: target.userId,
      title: 'Password Changed',
      message: 'Your account password was changed and other active sessions were signed out.',
      severity: 'INFO',
    });
    phase08Store.recordBeforeAfterAudit({
      userId: actor.userId,
      userRole: actor.role,
      actionType: 'CHANGE_PASSWORD',
      module: 'users',
      recordId: target.userId,
      beforeValues: null,
      afterValues: { passwordChangedAt: target.passwordChangedAt },
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      actionResult: 'SUCCESS',
    });

    return apiSuccess(res, { changed: true }, 'Password changed successfully.');
  });

  app.patch(
    '/api/users/:id/status',
    requireAuth,
    requirePermission('users', 'EDIT'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const target = store.findUserByUserId(req.params.id) ?? store.findUserByNumericId(Number(req.params.id));
      if (!target) return apiError(res, 'User not found.', 404);

      if (store.isMasterAdminUser(target)) {
        store.addSecurityLog({
          actorUserId: actor.userId,
          targetUserId: target.userId,
          eventType: 'UNAUTHORIZED_ACCESS',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Blocked attempt to alter protected Master Admin account ${target.userId}.`,
        });
        return apiError(res, 'Master Admin account is protected and cannot be suspended, deactivated, or downgraded.', 403);
      }

      if (actor.role === 'MANAGER' && target.role !== 'STAFF') {
        return apiError(res, 'Managers can only change status of STAFF accounts.', 403);
      }
      if (actor.userId === target.userId) {
        return apiError(res, 'You cannot suspend or deactivate your own account.', 400);
      }

      const nextStatus = String(req.body?.status ?? '').toUpperCase() as AccountStatus;
      if (!['ACTIVE', 'SUSPENDED', 'DEACTIVATED', 'REJECTED'].includes(nextStatus)) {
        return apiError(res, 'Invalid account status.', 422);
      }

      const prevStatus = target.status;
      target.status = nextStatus;
      target.updatedAt = new Date().toISOString();
      if (nextStatus === 'ACTIVE') {
        target.failedLoginAttempts = 0;
        target.lockedUntil = null;
      }

      // Immediately revoke sessions if suspended or deactivated
      if (nextStatus === 'SUSPENDED' || nextStatus === 'DEACTIVATED') {
        for (const s of store.sessions.values()) {
          if (s.userId === target.userId && s.status === 'ACTIVE') {
            s.status = 'REVOKED';
          }
        }
      }

      store.addSecurityLog({
        actorUserId: actor.userId,
        targetUserId: target.userId,
        eventType: 'ACCOUNT_STATUS_CHANGED',
        result: 'SUCCESS',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Changed ${target.userId} status from ${prevStatus} to ${nextStatus}.`,
      });
      store.addAuditLog({
        actorUserId: actor.userId,
        action: 'CHANGE_ACCOUNT_STATUS',
        targetType: 'user',
        targetId: target.userId,
        details: `Status transition: ${prevStatus} -> ${nextStatus}`,
        ipAddress: getClientIp(req),
      });
      phase08Store.recordBeforeAfterAudit({
        userId: actor.userId,
        userRole: actor.role,
        actionType: 'CHANGE_ACCOUNT_STATUS',
        module: 'users',
        recordId: target.userId,
        beforeValues: { status: prevStatus },
        afterValues: { status: nextStatus },
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        actionResult: 'SUCCESS',
      });

      return apiSuccess(
        res,
        store.sanitizePublicUser(target, actor.role),
        `Account ${target.userId} marked ${nextStatus}.`
      );
    }
  );

  app.delete(
    '/api/users/:id',
    requireAuth,
    requirePermission('users', 'DELETE'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      if (actor.role !== 'ADMIN') {
        return apiError(res, 'Only ADMIN can deactivate/delete user accounts.', 403);
      }
      const target = store.findUserByUserId(req.params.id) ?? store.findUserByNumericId(Number(req.params.id));
      if (!target) return apiError(res, 'User not found.', 404);
      if (store.isMasterAdminUser(target)) {
        store.addSecurityLog({
          actorUserId: actor.userId,
          targetUserId: target.userId,
          eventType: 'UNAUTHORIZED_ACCESS',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Blocked deletion attempt on protected Master Admin ${target.userId}.`,
        });
        return apiError(res, 'Master Admin account cannot be deleted or deactivated.', 403);
      }
      if (actor.userId === target.userId) {
        return apiError(res, 'Cannot delete your own active session account.', 400);
      }

      const prev = target.status;
      target.status = 'DEACTIVATED';
      target.updatedAt = new Date().toISOString();
      for (const s of store.sessions.values()) {
        if (s.userId === target.userId && s.status === 'ACTIVE') {
          s.status = 'REVOKED';
        }
      }
      store.addSecurityLog({
        actorUserId: actor.userId,
        targetUserId: target.userId,
        eventType: 'ACCOUNT_STATUS_CHANGED',
        result: 'SUCCESS',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Admin deactivated user ${target.userId} (previous: ${prev}).`,
      });
      return apiSuccess(res, { userId: target.userId, status: target.status }, `User ${target.userId} deactivated.`);
    }
  );

  // Authorized Admin-only Aadhaar reveal (never logged in plaintext)
  app.get('/api/users/:id/aadhaar', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      return apiError(res, 'Only ADMIN is authorized to decrypt sensitive Aadhaar records.', 403);
    }
    const target = store.findUserByUserId(req.params.id);
    if (!target || !target.aadhaarEncrypted) {
      return apiError(res, 'No Aadhaar record stored for this user.', 404);
    }
    const decrypted = decryptSensitiveField(target.aadhaarEncrypted);
    store.addAuditLog({
      actorUserId: actor.userId,
      action: 'AUTHORIZED_AADHAAR_ACCESS',
      targetType: 'user',
      targetId: target.userId,
      details: 'Authorized admin decrypted masked Aadhaar record (value omitted from log).',
      ipAddress: getClientIp(req),
    });
    return apiSuccess(res, {
      userId: target.userId,
      aadhaarFormatted: `${decrypted.slice(0, 4)}-${decrypted.slice(4, 8)}-${decrypted.slice(8, 12)}`,
      masked: maskAadhaar(target.aadhaarLast4),
    });
  });

  // ==========================================================================
  // REGISTRATION REQUESTS & APPROVAL WORKFLOW
  // (PUBLIC SELF-REGISTRATION DISABLED: ONLY AUTHENTICATED ADMIN/MANAGER)
  // ==========================================================================
  app.get(
    '/api/registration-requests',
    requireAuth,
    requirePermission('approvals', 'VIEW'),
    (_req, res) => {
      const safeRequests = store.registrationRequests.map((r) => ({
        id: r.id,
        requestId: r.requestId,
        applicantName: r.applicantName,
        requestedRole: r.requestedRole,
        mobile: r.mobile,
        email: r.email ?? '',
        address: r.address,
        designation: r.designation ?? '',
        departmentCode: r.departmentCode ?? 'DEPT-CSC',
        joiningDate: r.joiningDate ?? r.createdAt.slice(0, 10),
        aadhaarMasked: r.aadhaarLast4 ? `XXXX-XXXX-${r.aadhaarLast4}` : undefined,
        mobileVerified: r.mobileVerified,
        submittedBy: r.submittedBy,
        status: r.status,
        reviewedBy: r.reviewedBy ?? null,
        approvalDate: r.approvalDate ?? null,
        reviewNotes: r.reviewNotes ?? null,
        issuedUserId: r.issuedUserId ?? null,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
      }));
      return apiSuccess(res, safeRequests);
    }
  );

  app.post('/api/registration-requests', authRateLimiter, requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN' && actor.role !== 'MANAGER') {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'UNAUTHORIZED_ACCESS',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked ${actor.role} ${actor.userId} from submitting staff onboarding registration.`,
      });
      return apiError(
        res,
        'Public registration is disabled. Only Admin or Manager may initiate staff onboarding requests.',
        403
      );
    }

    const {
      applicantName,
      mobile,
      email,
      address,
      password,
      confirmPassword,
      mobileVerificationToken,
      aadhaarNumber,
      aadhaarConsent,
      designation,
      departmentCode,
      joiningDate,
    } = req.body ?? {};

    const errors: Record<string, string[]> = {};
    if (!applicantName || String(applicantName).trim().length < 2) {
      errors.applicantName = ['Applicant full name is required.'];
    }
    if (!mobile || String(mobile).trim().length < 8) {
      errors.mobile = ['Valid mobile number is required.'];
    }
    if (!address || String(address).trim().length < 4) {
      errors.address = ['Residential address is required.'];
    }
    const pwdErr = validateStrongPassword(password);
    if (pwdErr) {
      errors.password = [pwdErr];
    }
    if (password !== confirmPassword) {
      errors.confirmPassword = ['Passwords do not match.'];
    }
    if (Object.keys(errors).length > 0) {
      return apiError(res, 'Validation failed.', 422, errors);
    }

    const otpRecord = mobileVerificationToken
      ? store.otpChallenges.get(String(mobileVerificationToken))
      : undefined;
    const isMobileVerified = Boolean(
      otpRecord &&
        otpRecord.purpose === 'MOBILE_VERIFICATION' &&
        otpRecord.verified &&
        otpRecord.target === String(mobile).trim()
    );

    if (!isMobileVerified) {
      return apiError(
        res,
        'Mobile OTP verification must be completed before submitting a registration request.',
        422,
        { mobileVerificationToken: ['Complete mobile OTP verification first.'] }
      );
    }

    let aadhaarEncrypted: string | undefined;
    let aadhaarLast4: string | undefined;
    let aadhaarConsentAt: string | undefined;
    if (aadhaarNumber) {
      const cleaned = String(aadhaarNumber).replace(/\s|-/g, '');
      if (!/^\d{12}$/.test(cleaned) || !aadhaarConsent) {
        return apiError(res, 'Valid 12-digit Aadhaar and explicit consent are required.', 422);
      }
      aadhaarEncrypted = encryptSensitiveField(cleaned);
      aadhaarLast4 = cleaned.slice(-4);
      aadhaarConsentAt = new Date().toISOString();
    }

    const now = new Date().toISOString();
    const resolvedDept = departmentCode ? sanitizeText(String(departmentCode)).toUpperCase() : 'DEPT-CSC';
    const record = {
      id: store.registrationRequests.length + 1,
      requestId: store.nextRequestCode(),
      applicantName: sanitizeText(String(applicantName)),
      requestedRole: 'STAFF' as RoleName,
      mobile: sanitizeText(String(mobile)),
      email: email ? sanitizeText(String(email)) : undefined,
      address: sanitizeText(String(address)),
      designation: designation ? sanitizeText(String(designation)) : 'CSC Counter Operator',
      departmentCode: resolvedDept,
      joiningDate: joiningDate ? sanitizeText(String(joiningDate)) : now.slice(0, 10),
      aadhaarEncrypted,
      aadhaarLast4,
      aadhaarConsentAt,
      passwordHash: hashPassword(String(password)),
      mobileVerified: true,
      submittedBy: actor.userId,
      status: 'PENDING' as const,
      createdAt: now,
      updatedAt: now,
    };

    store.registrationRequests.unshift(record);
    store.otpChallenges.delete(String(mobileVerificationToken));

    store.addAuditLog({
      actorUserId: actor.userId,
      action: 'SUBMIT_REGISTRATION_REQUEST',
      targetType: 'registration_request',
      targetId: record.requestId,
      details: `${actor.role} ${actor.userId} submitted staff registration request for ${record.applicantName}.`,
      ipAddress: getClientIp(req),
    });
    store.addPhase02Notification({
      triggerType: 'STAFF_REGISTRATION_PENDING',
      recipientUserId: 'MC2627110001',
      title: `Staff Onboarding Request: ${record.requestId}`,
      message: `${actor.userId} submitted STAFF onboarding for ${record.applicantName} (${resolvedDept}).`,
      severity: 'INFO',
    });

    return apiSuccess(
      res,
      {
        requestId: record.requestId,
        status: record.status,
        requestedRole: record.requestedRole,
        submittedBy: record.submittedBy,
      },
      'Staff onboarding request submitted for Admin approval.',
      201
    );
  });

  app.post(
    '/api/registration-requests/:id/approve',
    requireAuth,
    requirePermission('approvals', 'APPROVE'),
    async (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const reqRecord = store.registrationRequests.find(
        (r) => r.requestId === req.params.id || String(r.id) === req.params.id
      );
      if (!reqRecord) return apiError(res, 'Registration request not found.', 404);
      if (reqRecord.status !== 'PENDING' && reqRecord.status !== 'CORRECTION_REQUIRED') {
        return apiError(res, `Request is already ${reqRecord.status}.`, 400);
      }
      if (reqRecord.requestedRole !== 'STAFF' && actor.role !== 'ADMIN') {
        return apiError(res, 'Only Admin can approve non-Staff requests.', 403);
      }

      const issuedUserId = await store.sequenceService.allocateNext(
        reqRecord.requestedRole,
        undefined,
        undefined,
        {
          actorUserId: actor.userId,
          departmentCode: reqRecord.departmentCode ?? 'DEPT-CSC',
        }
      );
      const now = new Date().toISOString();

      const newUser: ServerUser = {
        id: store.users.length + 1,
        userId: issuedUserId,
        isMasterAdmin: false,
        fullName: reqRecord.applicantName,
        role: reqRecord.requestedRole,
        mobile: reqRecord.mobile,
        email: reqRecord.email,
        address: reqRecord.address,
        designation: reqRecord.designation ?? 'CSC Counter Operator',
        departmentCode: reqRecord.departmentCode ?? 'DEPT-CSC',
        joiningDate: reqRecord.joiningDate ?? now.slice(0, 10),
        aadhaarEncrypted: reqRecord.aadhaarEncrypted,
        aadhaarLast4: reqRecord.aadhaarLast4,
        aadhaarConsentAt: reqRecord.aadhaarConsentAt,
        passwordHash: reqRecord.passwordHash,
        passwordAlgo: 'scrypt-v1',
        branch: 'Main Service Center',
        status: 'ACTIVE',
        mobileVerified: reqRecord.mobileVerified,
        emailVerified: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdBy: actor.userId,
        createdAt: now,
        updatedAt: now,
        passwordChangedAt: now,
        customPermissions: {},
      };
      store.users.unshift(newUser);
      phase08Store.pushPasswordHistory(newUser.userId, newUser.passwordHash);

      reqRecord.status = 'APPROVED';
      reqRecord.reviewedBy = actor.userId;
      reqRecord.approvalDate = now;
      reqRecord.reviewNotes = sanitizeText(String(req.body?.notes || 'Approved and activated.'));
      reqRecord.issuedUserId = issuedUserId;
      reqRecord.updatedAt = now;

      store.addAuditLog({
        actorUserId: actor.userId,
        action: 'APPROVE_REGISTRATION',
        targetType: 'registration_request',
        targetId: reqRecord.requestId,
        details: `Approved ${reqRecord.requestId}; issued User ID ${issuedUserId} for ${reqRecord.applicantName}.`,
        ipAddress: getClientIp(req),
      });
      store.addPhase02Notification({
        triggerType: 'STAFF_ACCOUNT_CREATED',
        recipientUserId: issuedUserId,
        title: `Staff Onboarding Approved: ${issuedUserId}`,
        message: `Your account ${issuedUserId} has been approved and activated.`,
        severity: 'INFO',
      });

      return apiSuccess(
        res,
        {
          requestId: reqRecord.requestId,
          status: reqRecord.status,
          issuedUserId,
          user: store.sanitizePublicUser(newUser, actor.role),
        },
        `Request approved. User ID ${issuedUserId} activated.`
      );
    }
  );

  app.post(
    '/api/registration-requests/:id/reject',
    requireAuth,
    requirePermission('approvals', 'APPROVE'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const reqRecord = store.registrationRequests.find(
        (r) => r.requestId === req.params.id || String(r.id) === req.params.id
      );
      if (!reqRecord) return apiError(res, 'Registration request not found.', 404);
      if (reqRecord.status === 'APPROVED') {
        return apiError(res, 'Cannot reject an already approved request.', 400);
      }

      const mode = req.body?.correction ? 'CORRECTION_REQUIRED' : 'REJECTED';
      const notes = sanitizeText(String(req.body?.notes || ''));
      if (!notes) {
        return apiError(res, 'Review notes or reason are required.', 422, {
          notes: ['Provide a reason for rejection or correction.'],
        });
      }

      const now = new Date().toISOString();
      reqRecord.status = mode;
      reqRecord.reviewedBy = actor.userId;
      reqRecord.approvalDate = now;
      reqRecord.reviewNotes = notes;
      reqRecord.updatedAt = now;

      store.addAuditLog({
        actorUserId: actor.userId,
        action: mode === 'REJECTED' ? 'REJECT_REGISTRATION' : 'REQUEST_CORRECTION',
        targetType: 'registration_request',
        targetId: reqRecord.requestId,
        details: `${mode} on ${reqRecord.requestId}: ${notes}`,
        ipAddress: getClientIp(req),
      });

      return apiSuccess(
        res,
        { requestId: reqRecord.requestId, status: reqRecord.status },
        mode === 'REJECTED' ? 'Registration request rejected.' : 'Correction requested.'
      );
    }
  );

  // ==========================================================================
  // ROLES & PERMISSION MATRIX
  // ==========================================================================
  app.get('/api/roles', requireAuth, (_req, res) => {
    const roles = (['ADMIN', 'MANAGER', 'STAFF', 'AUDITOR'] as RoleName[]).map((role) => ({
      role,
      userCount: store.users.filter((u) => u.role === role).length,
      defaultMatrix: ROLE_PERMISSION_MATRIX[role],
    }));
    return apiSuccess(res, roles);
  });

  app.get('/api/permissions', requireAuth, (_req, res) => {
    return apiSuccess(res, {
      modules: ALL_MODULES,
      permissionTypes: ALL_PERMISSION_TYPES,
      reportPermissions: REPORT_PERMISSION_KEYS,
      matrix: ROLE_PERMISSION_MATRIX,
      history: store.permissionHistory,
    });
  });

  app.put(
    '/api/users/:id/permissions',
    requireAuth,
    requirePermission('permissions', 'EDIT'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      // Strictly Admin-only for mutating permissions
      if (actor.role !== 'ADMIN') {
        store.addSecurityLog({
          actorUserId: actor.userId,
          eventType: 'UNAUTHORIZED_ACCESS',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `${actor.role} attempted unauthorized permission modification.`,
        });
        return apiError(res, 'Only ADMIN can modify user permissions.', 403);
      }

      const target = store.findUserByUserId(req.params.id);
      if (!target) return apiError(res, 'Target user not found.', 404);

      if (target.userId === actor.userId) {
        return apiError(res, 'Users cannot modify their own permissions.', 403);
      }
      if (store.isMasterAdminUser(target) || target.role === 'ADMIN') {
        store.addSecurityLog({
          actorUserId: actor.userId,
          targetUserId: target.userId,
          eventType: 'UNAUTHORIZED_ACCESS',
          result: 'BLOCKED',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Blocked attempt to alter protected Master Admin permissions on ${target.userId}.`,
        });
        return apiError(res, 'Admin and Master Admin permissions cannot be downgraded.', 403);
      }

      const updates = req.body?.permissions as Record<string, boolean> | undefined;
      if (!updates || typeof updates !== 'object') {
        return apiError(res, 'Permissions object is required.', 422);
      }

      const before = store.getEffectivePermissions(target);
      let changedCount = 0;

      for (const [key, val] of Object.entries(updates)) {
        const isReportPerm = (REPORT_PERMISSION_KEYS as readonly string[]).includes(key);
        const isCscPerm = (CSC_OPERATOR_PERMISSION_KEYS as readonly string[]).includes(key);
        const [mod, perm] = key.split('.') as [ModuleKey, PermissionType];
        const isModulePerm = ALL_MODULES.includes(mod) && ALL_PERMISSION_TYPES.includes(perm);
        if (!isModulePerm && !isReportPerm && !isCscPerm) {
          continue;
        }
        const boolVal = Boolean(val);
        if (before[key as ReportPermissionKey] !== boolVal) {
          target.customPermissions[key] = boolVal;
          changedCount += 1;
          store.permissionHistory.unshift({
            id: store.permissionHistory.length + 1,
            actorUserId: actor.userId,
            targetUserId: target.userId,
            permissionKey: key,
            previousValue: before[key],
            newValue: boolVal,
            createdAt: new Date().toISOString(),
          });
        }
      }

      target.updatedAt = new Date().toISOString();

      if (changedCount > 0) {
        store.addSecurityLog({
          actorUserId: actor.userId,
          targetUserId: target.userId,
          eventType: 'PERMISSION_CHANGED',
          result: 'SUCCESS',
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          summary: `Updated ${changedCount} permission(s) for ${target.userId}.`,
        });
        store.addAuditLog({
          actorUserId: actor.userId,
          action: 'UPDATE_USER_PERMISSIONS',
          targetType: 'user',
          targetId: target.userId,
          details: `Modified ${changedCount} permission override(s) on ${target.userId}.`,
          ipAddress: getClientIp(req),
        });
        const after = store.getEffectivePermissions(target);
        const beforeDiff: Record<string, boolean> = {};
        const afterDiff: Record<string, boolean> = {};
        for (const key of Object.keys(after)) {
          if (before[key] !== after[key]) {
            beforeDiff[key] = Boolean(before[key]);
            afterDiff[key] = Boolean(after[key]);
          }
        }
        phase08Store.recordBeforeAfterAudit({
          userId: actor.userId,
          userRole: actor.role,
          actionType: 'UPDATE_USER_PERMISSIONS',
          module: 'permissions',
          recordId: target.userId,
          beforeValues: beforeDiff,
          afterValues: afterDiff,
          ipAddress: getClientIp(req),
          deviceInfo: getDeviceInfo(req),
          actionResult: 'SUCCESS',
        });
      }

      return apiSuccess(
        res,
        {
          userId: target.userId,
          permissions: store.getEffectivePermissions(target),
        },
        `Updated permissions for ${target.userId}.`
      );
    }
  );

  // ==========================================================================
  // SECURITY LOGS, AUDIT LOGS & SESSION MANAGEMENT
  // ==========================================================================
  app.get(
    '/api/security-logs',
    requireAuth,
    requirePermission('security_logs', 'VIEW'),
    (req: AuthedRequest, res) => {
      const actor = req.authUser!;
      const logs =
        actor.role === 'ADMIN'
          ? store.securityLogs
          : store.securityLogs.filter(
              (l) =>
                !l.actorUserId.startsWith('MC-AD-') &&
                l.actorUserId !== 'MC2627110001' &&
                l.actorUserId !== 'MC262711001'
            );
      return apiSuccess(res, logs);
    }
  );

  app.get(
    '/api/audit-logs',
    requireAuth,
    requirePermission('security_logs', 'VIEW'),
    (_req, res) => {
      return apiSuccess(res, store.auditLogs);
    }
  );

  app.get('/api/sessions', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const currentSessionId = req.authSession!.id;
    const list = Array.from(store.sessions.values())
      .filter((s) => (actor.role === 'ADMIN' ? true : s.userId === actor.userId))
      .map((s) => ({
        id: s.id,
        userId: s.userId,
        role: s.role,
        ipAddress: s.ipAddress,
        deviceInfo: s.deviceInfo,
        rememberMe: s.rememberMe,
        status: s.expiresAt <= Date.now() && s.status === 'ACTIVE' ? 'EXPIRED' : s.status,
        createdAt: s.createdAt,
        expiresAt: new Date(s.expiresAt).toISOString(),
        isCurrent: s.id === currentSessionId,
      }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    return apiSuccess(res, list);
  });

  app.delete('/api/sessions/:id', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const targetSession = Array.from(store.sessions.values()).find(
      (s) => s.id === req.params.id
    );
    if (!targetSession) return apiError(res, 'Session not found.', 404);

    if (actor.role !== 'ADMIN' && targetSession.userId !== actor.userId) {
      return apiError(res, 'Forbidden: cannot revoke another user session.', 403);
    }

    targetSession.status = 'REVOKED';
    if (targetSession.id === req.authSession!.id) {
      clearSessionCookies(res);
    }

    store.addSecurityLog({
      actorUserId: actor.userId,
      targetUserId: targetSession.userId,
      eventType: 'SESSION_REVOKED',
      result: 'SUCCESS',
      ipAddress: getClientIp(req),
      deviceInfo: getDeviceInfo(req),
      summary: `Revoked session ${targetSession.id} for ${targetSession.userId}.`,
    });

    return apiSuccess(res, { revoked: true, id: targetSession.id }, 'Session revoked.');
  });

  // ==========================================================================
  // PHASE 02 FINAL MASTER: DEPARTMENTS, 3-TIER SERVICE PERMISSIONS & NOTIFICATIONS
  // ==========================================================================
  app.get('/api/departments', requireAuth, (_req, res) => {
    return apiSuccess(res, store.departments);
  });

  app.post('/api/departments', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      return apiError(res, 'Only ADMIN can create or modify departments.', 403);
    }
    const { code, name, description, headUserId } = req.body ?? {};
    if (!code || !name) {
      return apiError(res, 'Department code and name are required.', 422);
    }
    const normCode = sanitizeText(String(code)).toUpperCase();
    if (store.departments.some((d) => d.code === normCode)) {
      return apiError(res, `Department ${normCode} already exists.`, 409);
    }
    const now = new Date().toISOString();
    const dept = {
      id: store.departments.length + 1,
      code: normCode,
      name: sanitizeText(String(name)),
      description: sanitizeText(String(description || '')),
      headUserId: headUserId ? sanitizeText(String(headUserId)) : undefined,
      status: 'ACTIVE' as const,
      createdAt: now,
      updatedAt: now,
    };
    store.departments.push(dept);
    return apiSuccess(res, dept, `Department ${dept.code} created.`, 201);
  });

  app.get('/api/service-permissions/overview', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    store.expireStaleServicePermissions();

    const managerAssignments =
      actor.role === 'ADMIN' || actor.role === 'AUDITOR'
        ? store.managerServiceAssignments
        : actor.role === 'MANAGER'
          ? store.managerServiceAssignments.filter((a) => a.managerUserId === actor.userId)
          : [];

    const staffRequests =
      actor.role === 'ADMIN' || actor.role === 'AUDITOR'
        ? store.staffServiceRequests
        : actor.role === 'MANAGER'
          ? store.staffServiceRequests.filter((r) => r.managerUserId === actor.userId)
          : store.staffServiceRequests.filter((r) => r.staffUserId === actor.userId);

    const staffPermissions =
      actor.role === 'ADMIN' || actor.role === 'AUDITOR'
        ? store.staffServicePermissions
        : actor.role === 'MANAGER'
          ? store.staffServicePermissions.filter((p) => p.managerUserId === actor.userId)
          : store.staffServicePermissions.filter((p) => p.staffUserId === actor.userId);

    const approvalLogs =
      actor.role === 'ADMIN' || actor.role === 'AUDITOR'
        ? store.serviceApprovalLogs
        : actor.role === 'MANAGER'
          ? store.serviceApprovalLogs.filter(
              (l) => l.managerUserId === actor.userId || l.actorUserId === actor.userId
            )
          : store.serviceApprovalLogs.filter((l) => l.staffUserId === actor.userId);

    return apiSuccess(res, {
      departments: store.departments,
      managerAssignments,
      staffRequests,
      staffPermissions,
      approvalLogs,
      availableServices: erpStore.services.map((s) => ({
        serviceId: s.serviceId,
        name: s.name,
        category: s.categoryName || s.categoryId,
        status: s.status,
      })),
    });
  });

  app.post('/api/service-permissions/manager-assignments', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'UNAUTHORIZED_ACCESS',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `${actor.role} attempted unauthorized Admin manager-service assignment.`,
      });
      return apiError(res, 'Only ADMIN can assign services to Managers.', 403);
    }
    const {
      managerUserId,
      serviceId,
      serviceName,
      departmentCode,
      permissions,
      effectiveDate,
      expiryDate,
      notes,
    } = req.body ?? {};
    if (!managerUserId || !serviceId) {
      return apiError(res, 'managerUserId and serviceId are required.', 422);
    }
    const catalogSvc = erpStore.services.find((s) => s.serviceId === String(serviceId));
    try {
      const assignment = store.assignServiceToManager({
        actor,
        managerUserId: String(managerUserId),
        serviceId: String(serviceId),
        serviceName: serviceName ? sanitizeText(String(serviceName)) : catalogSvc?.name || String(serviceId),
        departmentCode: departmentCode ? sanitizeText(String(departmentCode)).toUpperCase() : 'DEPT-CSC',
        permissions: Array.isArray(permissions) ? permissions : ['VIEW', 'ADD', 'EDIT', 'ASSIGN', 'EXECUTE'],
        effectiveDate: effectiveDate ? String(effectiveDate) : undefined,
        expiryDate: expiryDate ? String(expiryDate) : null,
        notes: notes ? sanitizeText(String(notes)) : undefined,
      });
      return apiSuccess(res, assignment, `Assigned ${assignment.serviceId} to ${assignment.managerUserId}.`, 201);
    } catch (err) {
      return apiError(res, err instanceof Error ? err.message : 'Unable to assign service.', 422);
    }
  });

  app.patch('/api/service-permissions/manager-assignments/:code/status', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      return apiError(res, 'Only ADMIN can suspend, revoke, or reactivate Manager service assignments.', 403);
    }
    const status = String(req.body?.status ?? '').toUpperCase() as 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
    if (!['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(status)) {
      return apiError(res, 'Invalid status (ACTIVE, SUSPENDED, or REVOKED required).', 422);
    }
    try {
      const result = store.updateManagerServiceAssignmentStatus({
        actor,
        assignmentCode: req.params.code,
        status,
        reason: req.body?.reason ? sanitizeText(String(req.body.reason)) : undefined,
      });
      return apiSuccess(
        res,
        result,
        `Manager assignment ${req.params.code} marked ${status}${result.cascadedStaffCount > 0 ? ` (cascaded to ${result.cascadedStaffCount} Staff permission(s))` : ''}.`
      );
    } catch (err) {
      return apiError(res, err instanceof Error ? err.message : 'Assignment not found.', 404);
    }
  });

  app.post('/api/service-permissions/staff-requests', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'MANAGER') {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'UNAUTHORIZED_ACCESS',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked ${actor.role} ${actor.userId} from Manager Staff-service request endpoint.`,
      });
      return apiError(
        res,
        'Only MANAGER may submit Staff service permission requests within Admin-assigned services.',
        403
      );
    }
    const { staffUserId, serviceId, requestedPermissions, reason } = req.body ?? {};
    if (!staffUserId || !serviceId) {
      return apiError(res, 'staffUserId and serviceId are required.', 422);
    }
    try {
      const requestRecord = store.submitStaffServiceRequest({
        actor,
        staffUserId: String(staffUserId),
        serviceId: String(serviceId),
        requestedPermissions: Array.isArray(requestedPermissions) ? requestedPermissions : ['VIEW', 'EXECUTE'],
        reason: reason ? sanitizeText(String(reason)) : undefined,
      });
      return apiSuccess(
        res,
        requestRecord,
        `Staff service request ${requestRecord.requestCode} submitted (Pending Admin Approval).`,
        201
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unable to submit request.';
      const status = msg.includes('not actively assigned') ? 403 : 422;
      return apiError(res, msg, status);
    }
  });

  app.post('/api/service-permissions/staff-requests/:code/decide', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'UNAUTHORIZED_ACCESS',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked ${actor.role} ${actor.userId} from approving/rejecting Staff service request ${req.params.code}.`,
      });
      return apiError(res, 'Only ADMIN can approve or reject Staff service permission requests.', 403);
    }
    const decision = String(req.body?.decision ?? '').toUpperCase();
    if (!['APPROVE', 'REJECT'].includes(decision)) {
      return apiError(res, 'Decision must be APPROVE or REJECT.', 422);
    }
    try {
      const result = store.decideStaffServiceRequest({
        actor,
        requestCode: req.params.code,
        approve: decision === 'APPROVE',
        notes: req.body?.notes ? sanitizeText(String(req.body.notes)) : undefined,
        expiryDate: req.body?.expiryDate ? String(req.body.expiryDate) : undefined,
      });
      return apiSuccess(
        res,
        result,
        decision === 'APPROVE'
          ? `Staff service request ${req.params.code} approved and activated.`
          : `Staff service request ${req.params.code} rejected.`
      );
    } catch (err) {
      return apiError(res, err instanceof Error ? err.message : 'Decision failed.', 422);
    }
  });

  app.patch('/api/service-permissions/staff-permissions/:code/status', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    if (actor.role !== 'ADMIN') {
      return apiError(res, 'Only ADMIN can modify active Staff service permission states.', 403);
    }
    const status = String(req.body?.status ?? '').toUpperCase() as 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
    if (!['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(status)) {
      return apiError(res, 'Invalid status (ACTIVE, SUSPENDED, or REVOKED required).', 422);
    }
    try {
      const updated = store.updateStaffServicePermissionStatus({
        actor,
        permissionCode: req.params.code,
        status,
        reason: req.body?.reason ? sanitizeText(String(req.body.reason)) : undefined,
      });
      return apiSuccess(res, updated, `Staff permission ${req.params.code} marked ${status}.`);
    } catch (err) {
      return apiError(res, err instanceof Error ? err.message : 'Unable to update status.', 422);
    }
  });

  app.post('/api/service-permissions/check', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const serviceId = String(req.body?.serviceId ?? '');
    const permission = (String(req.body?.permission ?? 'EXECUTE').toUpperCase()) as PermissionType;
    if (!serviceId) {
      return apiError(res, 'serviceId is required.', 422);
    }
    const check = store.checkServicePermissionStrict(actor, serviceId, permission);
    return apiSuccess(res, { serviceId, permission, ...check });
  });

  app.post('/api/service-permissions/execute', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const serviceId = String(req.body?.serviceId ?? '');
    const permission = (String(req.body?.permission ?? 'EXECUTE').toUpperCase()) as PermissionType;
    if (!serviceId) {
      return apiError(res, 'serviceId is required.', 422);
    }
    const check = store.checkServicePermissionStrict(actor, serviceId, permission);
    if (!check.allowed) {
      store.addSecurityLog({
        actorUserId: actor.userId,
        eventType: 'UNAUTHORIZED_ACCESS',
        result: 'BLOCKED',
        ipAddress: getClientIp(req),
        deviceInfo: getDeviceInfo(req),
        summary: `Blocked ${actor.role} ${actor.userId} executing ${serviceId}.${permission}: ${check.reason}`,
      });
      return apiError(res, `Forbidden (Default Deny): ${check.reason}`, 403);
    }
    return apiSuccess(res, { executed: true, serviceId, permission, reason: check.reason }, 'Service operation authorized.');
  });

  app.get('/api/notifications/security', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const list =
      actor.role === 'ADMIN'
        ? store.phase02Notifications
        : store.phase02Notifications.filter((n) => n.recipientUserId === actor.userId);
    return apiSuccess(res, list);
  });

  app.patch('/api/notifications/security/:code/read', requireAuth, (req: AuthedRequest, res) => {
    const actor = req.authUser!;
    const notif = store.phase02Notifications.find((n) => n.notificationCode === req.params.code);
    if (!notif) return apiError(res, 'Notification not found.', 404);
    if (actor.role !== 'ADMIN' && notif.recipientUserId !== actor.userId) {
      return apiError(res, 'Forbidden.', 403);
    }
    notif.isRead = true;
    return apiSuccess(res, notif, 'Notification marked read.');
  });

  // ==========================================================================
  // PHASE 03: MASTER SETTINGS, SERVICE RATES, BACKUPS, DAILY CASH, INTEGRATIONS
  // ==========================================================================
  registerPhase03Routes(app, store, phase03Store, requireAuth);

  // ==========================================================================
  // ENTERPRISE ERP Q1-51: CUSTOMERS CRM, SERVICES/FORMS, WORKFLOWS & FINANCE
  // ==========================================================================
  registerErpRoutes(app, store, phase03Store, erpStore, requireAuth, financeStore);

  // ==========================================================================
  // PHASE 05: CENTRAL FINANCIAL ENGINE (MODULES 01-94)
  // ==========================================================================
  registerFinanceRoutes(app, store, financeStore, requireAuth);

  // ==========================================================================
  // PHASE 07: ADVANCED REPORTS, PDF, EXCEL, ANALYTICS & PRINTING
  // ==========================================================================
  registerReportRoutes(
    app,
    store,
    phase03Store,
    erpStore,
    financeStore,
    reportStore,
    reportScheduler,
    requireAuth,
    cscStore
  );

  // ==========================================================================
  // DIGITAL SERVICE CENTER / CSC ENTERPRISE MODULE (PARTS 1-18)
  // ==========================================================================
  registerCscRoutes(app, store, cscStore, requireAuth);

  // ==========================================================================
  // PHASE 08: ENTERPRISE SECURITY, BACKUP, DISASTER RECOVERY & DATA PROTECTION
  // ==========================================================================
  registerPhase08Routes(app, store, phase08Store, backupScheduler, requireAuth);

  // ==========================================================================
  // PHASE 09: ENTERPRISE TESTING, QA, SECURITY AUDIT, BUGS & RELEASE GATE
  // ==========================================================================
  registerQaRoutes(
    app,
    store,
    phase03Store,
    erpStore,
    financeStore,
    reportStore,
    phase08Store,
    qaStore,
    requireAuth
  );

  if (options.enableReportScheduler !== false && process.env.NODE_ENV !== 'test') {
    reportScheduler.start(60_000);
  }
  if (options.enableBackupScheduler !== false && process.env.NODE_ENV !== 'test') {
    backupScheduler.start(120_000);
  }

  return app;
}
