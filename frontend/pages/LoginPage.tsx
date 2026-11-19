import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  MessageSquareText,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  User,
} from 'lucide-react';
import { BrandLogo } from '../components/BrandLogo';
import { Button } from '../components/Button';
import { BRAND } from '../assets/brand';
import {
  isExpressBackendOffline,
  securityRequest,
  setCsrfToken,
} from '../services/securityApi';
import {
  firebaseInitError,
  getFirebaseTotpStatus,
  isFirebaseConfigured,
  setFirebase2faPending,
  signInWithCredentialsFirebase,
  signInWithGoogleFirebase,
  signOutFirebase,
  verifyFirebaseConnectivity,
  verifyFirebaseTotpCode,
} from '../services/firebase';
import { UserProfile } from '../modules/types';

type AuthStep =
  | 'login'
  | 'validating'
  | 'otp-verify'
  | 'forgot-password'
  | 'reset-password';

const CAPTCHA_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function randomCaptchaInt(maxExclusive: number): number {
  if (typeof window !== 'undefined' && window.crypto?.getRandomValues) {
    const buf = new Uint32Array(1);
    window.crypto.getRandomValues(buf);
    return buf[0] % maxExclusive;
  }
  return Math.floor(Math.random() * maxExclusive);
}

function generateClientCaptcha(): {
  id: string;
  code: string;
  svg: string;
} {
  let code = '';
  for (let i = 0; i < 5; i += 1) {
    code += CAPTCHA_CHARSET[randomCaptchaInt(CAPTCHA_CHARSET.length)];
  }
  const id = `client-${Date.now().toString(36)}-${randomCaptchaInt(100000).toString(36)}`;
  const palette = ['#0a0a0a', '#1e3a8a', '#171717', '#0f172a'];

  const letters = code
    .split('')
    .map((ch, idx) => {
      const x = 18 + idx * 24;
      const y = 25 + randomCaptchaInt(6) - 1;
      const rot = randomCaptchaInt(21) - 10;
      const color = palette[randomCaptchaInt(palette.length)];
      return `<text x="${x}" y="${y}" transform="rotate(${rot} ${x} ${y})" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="20" font-weight="700" fill="${color}">${ch}</text>`;
    })
    .join('');

  const line1Y1 = 8 + randomCaptchaInt(24);
  const line1Y2 = 8 + randomCaptchaInt(24);
  const line2Y1 = 8 + randomCaptchaInt(24);
  const line2Y2 = 8 + randomCaptchaInt(24);
  const line3Y1 = 10 + randomCaptchaInt(20);
  const line3Y2 = 10 + randomCaptchaInt(20);

  const dots = Array.from({ length: 8 }, () => {
    const cx = 8 + randomCaptchaInt(128);
    const cy = 6 + randomCaptchaInt(28);
    return `<circle cx="${cx}" cy="${cy}" r="1" fill="#94a3b8" opacity="0.55"/>`;
  }).join('');

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="144" height="40" viewBox="0 0 144 40" role="img" aria-label="Security verification code">
    <rect width="144" height="40" rx="4" fill="#fafafa" stroke="#e5e5e5"/>
    <line x1="6" y1="${line1Y1}" x2="138" y2="${line1Y2}" stroke="#cbd5e1" stroke-width="1.1"/>
    <line x1="8" y1="${line2Y1}" x2="136" y2="${line2Y2}" stroke="#d4d4d8" stroke-width="1"/>
    <line x1="12" y1="${line3Y1}" x2="132" y2="${line3Y2}" stroke="#93c5fd" stroke-width="0.9" opacity="0.65"/>
    ${dots}
    ${letters}
  </svg>`;

  return { id, code, svg };
}

interface LoginPageProps {
  onLoginSuccess: (
    user: UserProfile,
    permissions: Record<string, boolean>,
    sessionMeta?: { expiresAt?: string; rememberMe?: boolean }
  ) => void;
  onShowToast: (
    type: 'success' | 'error' | 'info',
    title: string,
    description?: string
  ) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLoginSuccess,
  onShowToast,
}) => {
  const [step, setStep] = useState<AuthStep>('login');

  // Step 1: Login Form State (never prefilled in Production builds)
  const [userId, setUserId] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // CAPTCHA State (initialized synchronously so the CAPTCHA box is never blank on load)
  const [initialCaptcha] = useState(() => generateClientCaptcha());
  const [captchaId, setCaptchaId] = useState(initialCaptcha.id);
  const [captchaSvg, setCaptchaSvg] = useState(initialCaptcha.svg);
  const [clientCaptchaCode, setClientCaptchaCode] = useState(initialCaptcha.code);
  const [captchaSource, setCaptchaSource] = useState<'server' | 'client'>('client');
  const [captchaAnswer, setCaptchaAnswer] = useState('');

  // Step 2 & Step 3: 2FA Verification State (SMS active default + Google Authenticator TOTP)
  const otpChannel = 'SMS' as const;
  const [authMode, setAuthMode] = useState<'express' | 'firebase'>('express');
  const [active2faMethod, setActive2faMethod] = useState<'SMS' | 'TOTP'>('SMS');
  const [totpAvailable, setTotpAvailable] = useState(false);
  const [otpChallengeId, setOtpChallengeId] = useState('');
  const [otpMaskedMobile, setOtpMaskedMobile] = useState('');
  const [otpDeliveryDetail, setOtpDeliveryDetail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [sandboxOtp, setSandboxOtp] = useState<string | null>(null);
  const [providerConfigured, setProviderConfigured] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [validationStatusText, setValidationStatusText] = useState(
    'Validating User ID, Password, and CAPTCHA via Firebase SDK...'
  );
  const [pendingFirebaseAuth, setPendingFirebaseAuth] = useState<{
    user: UserProfile;
    permissions: Record<string, boolean>;
    uid: string;
  } | null>(null);

  // Forgot & Reset Password State
  const [resetUserId, setResetUserId] = useState('');
  const [resetChallengeId, setResetChallengeId] = useState('');
  const [resetOtp, setResetOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [firebaseLoading, setFirebaseLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const expressOnlineRef = useRef<boolean | null>(
    isExpressBackendOffline() ? false : null
  );
  const prevStepRef = useRef<AuthStep | null>(null);
  const firebaseConfigured = isFirebaseConfigured();

  const applyClientCaptcha = useCallback(() => {
    const next = generateClientCaptcha();
    setCaptchaId(next.id);
    setCaptchaSvg(next.svg);
    setClientCaptchaCode(next.code);
    setCaptchaSource('client');
    setCaptchaAnswer('');
  }, []);

  const loadCaptcha = useCallback(
    async (clearError = false, forceNew = true) => {
      if (clearError) {
        setErrorBanner(null);
      }

      if (expressOnlineRef.current === false || isExpressBackendOffline()) {
        expressOnlineRef.current = false;
        if (forceNew) {
          applyClientCaptcha();
        }
        return;
      }

      try {
        const res = await securityRequest<{
          challengeId: string;
          svg: string;
        }>('/api/auth/captcha');
        if (res.data?.svg && res.data?.challengeId) {
          setCaptchaId(res.data.challengeId);
          setCaptchaSvg(res.data.svg);
          setClientCaptchaCode('');
          setCaptchaSource('server');
          setCaptchaAnswer('');
          expressOnlineRef.current = true;
        } else {
          expressOnlineRef.current = false;
          applyClientCaptcha();
        }
      } catch {
        expressOnlineRef.current = false;
        if (forceNew) {
          applyClientCaptcha();
        }
      }
    },
    [applyClientCaptcha]
  );

  useEffect(() => {
    const prevStep = prevStepRef.current;
    prevStepRef.current = step;
    if (step === 'login') {
      const returningToLogin =
        prevStep !== null && prevStep !== 'login' && prevStep !== 'validating';
      loadCaptcha(false, returningToLogin);
    }
  }, [step, loadCaptcha]);

  useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setInterval(() => {
      setResendCooldown((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [resendCooldown]);

  const handleBackToLogin = async () => {
    setErrorBanner(null);
    setFirebase2faPending(false);
    if (pendingFirebaseAuth) {
      try {
        await signOutFirebase();
      } catch {
        // Ignore cleanup failure
      }
      setPendingFirebaseAuth(null);
    }
    setOtpCode('');
    setTotpCode('');
    setOtpChallengeId('');
    setSandboxOtp(null);
    setStep('login');
  };

  // Step 1 -> Step 2 (Credential & Firebase SDK validation) -> Step 3 (SMS / Google Authenticator 2FA)
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorBanner(null);
    if (!userId.trim() || !password.trim() || !captchaAnswer.trim()) {
      setErrorBanner('User ID, Password, and CAPTCHA code are all required.');
      return;
    }

    const normalizedCaptchaInput = captchaAnswer.trim().toUpperCase();
    if (captchaSource === 'client') {
      if (!clientCaptchaCode || normalizedCaptchaInput !== clientCaptchaCode) {
        const msg =
          'Invalid CAPTCHA verification code. Please enter the exact 5-character code shown.';
        setErrorBanner(msg);
        onShowToast('error', 'CAPTCHA Verification Failed', msg);
        applyClientCaptcha();
        return;
      }
    } else if (normalizedCaptchaInput.length !== 5) {
      const msg = 'Please enter the full 5-character CAPTCHA verification code.';
      setErrorBanner(msg);
      onShowToast('error', 'CAPTCHA Verification Failed', msg);
      return;
    }

    setLoading(true);
    setStep('validating');
    setValidationStatusText(
      'Step 2: Verifying credentials via Firebase SDK & Security Gateway...'
    );

    try {
      // Probe Firebase SDK connectivity as part of Step 2 validation
      const fbConn = await verifyFirebaseConnectivity();
      if (fbConn.configured && fbConn.connected) {
        setValidationStatusText(
          'Firebase SDK connected. Authenticating User ID and triggering 2FA challenge...'
        );
      }

      if (expressOnlineRef.current !== false && !isExpressBackendOffline()) {
        try {
          const res = await securityRequest<{
            otpRequired: boolean;
            challengeId: string;
            channel?: 'SMS';
            deliveryDetail?: string;
            maskedMobile: string;
            resendCooldownSeconds: number;
            providerConfigured: boolean;
            sandboxOtpPreview?: string;
            totpEnabled?: boolean;
          }>('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({
              userId: userId.trim().includes('@') ? userId.trim() : userId.trim().toUpperCase(),
              password,
              captchaId,
              captchaAnswer: normalizedCaptchaInput,
              rememberMe,
              otpChannel,
            }),
          });

          expressOnlineRef.current = true;
          setAuthMode('express');
          setPendingFirebaseAuth(null);
          setOtpChallengeId(res.data.challengeId);
          setOtpMaskedMobile(res.data.maskedMobile);
          setOtpDeliveryDetail(res.data.deliveryDetail || '');
          setProviderConfigured(res.data.providerConfigured);
          setSandboxOtp(res.data.sandboxOtpPreview ?? null);
          setResendCooldown(res.data.resendCooldownSeconds);
          setTotpAvailable(Boolean(res.data.totpEnabled));
          setActive2faMethod('SMS');
          setOtpCode('');
          setTotpCode('');
          setStep('otp-verify');
          onShowToast(
            'info',
            'Step 2 Verified · 2FA Required',
            res.data.totpEnabled
              ? 'Enter your SMS OTP or 6-digit Google Authenticator code.'
              : 'Enter the 6-digit SMS OTP to access the Master Dashboard.'
          );
          return;
        } catch (expressErr) {
          const msg = expressErr instanceof Error ? expressErr.message : '';
          const isConnectivityMiss =
            isExpressBackendOffline() ||
            msg.includes('Backend API server is not') ||
            msg.includes('Failed to fetch');
          if (!isConnectivityMiss) {
            throw expressErr;
          }
          expressOnlineRef.current = false;
        }
      }

      // Firebase SDK Direct Credential Authentication Path (when Express gateway is offline)
      if (!firebaseConfigured) {
        throw new Error(
          firebaseInitError ||
            'Neither the Express API server nor Firebase SDK is configured.'
        );
      }

      setFirebase2faPending(true);
      const fbAuthResult = await signInWithCredentialsFirebase(userId, password);
      const totpStatus = await getFirebaseTotpStatus(fbAuthResult.uid);

      setAuthMode('firebase');
      setPendingFirebaseAuth(fbAuthResult);
      setTotpAvailable(totpStatus.totpEnabled);
      setActive2faMethod(totpStatus.totpEnabled ? 'TOTP' : 'SMS');
      setOtpChallengeId('');
      setOtpMaskedMobile(fbAuthResult.user.mobile || fbAuthResult.user.email || userId.trim());
      setOtpDeliveryDetail(
        totpStatus.totpEnabled
          ? 'Firebase Auth Verified · Google Authenticator TOTP Ready'
          : 'Firebase Auth Verified · SMS Gateway Offline'
      );
      setProviderConfigured(false);
      setSandboxOtp(null);
      setOtpCode('');
      setTotpCode('');
      setStep('otp-verify');
      onShowToast(
        'info',
        'Firebase Credentials Verified',
        totpStatus.totpEnabled
          ? 'Complete Step 3 with your 6-digit Google Authenticator code.'
          : 'Complete Step 3 two-factor verification to enter the dashboard.'
      );
    } catch (err) {
      setFirebase2faPending(false);
      let message = err instanceof Error ? err.message : 'Login failed.';
      if (message.includes('auth/operation-not-allowed')) {
        message =
          'Firebase Email/Password sign-in is disabled for this project. Use "Sign in with Google (Firebase)" or connect the Express backend.';
      } else if (
        message.includes('auth/invalid-credential') ||
        message.includes('auth/wrong-password') ||
        message.includes('auth/user-not-found')
      ) {
        message = 'Invalid User ID / Email or Password.';
      }
      setErrorBanner(message);
      onShowToast('error', 'Authentication Failed', message);
      setStep('login');
      loadCaptcha(false, true);
    } finally {
      setLoading(false);
    }
  };

  const handleFirebaseGoogleSignIn = async () => {
    setErrorBanner(null);
    if (!firebaseConfigured) {
      const msg =
        firebaseInitError ||
        'Firebase is not configured. Set VITE_FIREBASE_* environment variables.';
      setErrorBanner(msg);
      onShowToast('error', 'Firebase Configuration Missing', msg);
      return;
    }

    setFirebaseLoading(true);
    setFirebase2faPending(true);
    try {
      const { user, permissions, uid } = await signInWithGoogleFirebase();
      const totpStatus = await getFirebaseTotpStatus(uid);

      if (totpStatus.totpEnabled) {
        setAuthMode('firebase');
        setPendingFirebaseAuth({ user, permissions, uid });
        setTotpAvailable(true);
        setActive2faMethod('TOTP');
        setOtpMaskedMobile(user.email || user.mobile || user.userId);
        setOtpDeliveryDetail('Google Sign-In Verified · Google Authenticator Required');
        setProviderConfigured(false);
        setSandboxOtp(null);
        setOtpCode('');
        setTotpCode('');
        setStep('otp-verify');
        onShowToast(
          'info',
          'Step 3: 2FA Required',
          'Enter your 6-digit Google Authenticator code for final Master Dashboard access.'
        );
        return;
      }

      setFirebase2faPending(false);
      onShowToast(
        'success',
        `Signed in as ${user.role}`,
        `Connected live to Firebase (${user.userId})`
      );
      onLoginSuccess(user, permissions);
    } catch (err) {
      setFirebase2faPending(false);
      const message = err instanceof Error ? err.message : 'Firebase Google sign-in failed.';
      setErrorBanner(message);
      onShowToast('error', 'Firebase Sign-In Failed', message);
    } finally {
      setFirebaseLoading(false);
    }
  };

  const handleVerifyLoginOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorBanner(null);

    if (authMode === 'firebase') {
      if (active2faMethod === 'SMS') {
        const msg =
          'Live SMS OTP delivery requires the Express SMS gateway. Please switch to the Google Authenticator (TOTP) input below or link TOTP in Security Settings.';
        setErrorBanner(msg);
        onShowToast('info', 'Use Google Authenticator TOTP', msg);
        return;
      }
      if (!pendingFirebaseAuth) {
        setErrorBanner('Your verification session expired. Please sign in again.');
        await handleBackToLogin();
        return;
      }
      const cleanTotp = totpCode.trim();
      if (!/^\d{6}$/.test(cleanTotp)) {
        setErrorBanner('Enter the 6-digit Google Authenticator code.');
        return;
      }

      setLoading(true);
      try {
        const valid = await verifyFirebaseTotpCode(cleanTotp, pendingFirebaseAuth.uid);
        if (!valid) {
          throw new Error('Invalid 6-digit Google Authenticator code. Please check your app and try again.');
        }
        const { user, permissions } = pendingFirebaseAuth;
        setFirebase2faPending(false);
        setPendingFirebaseAuth(null);
        onShowToast(
          'success',
          `Master Access Granted (${user.role})`,
          `Verified via Google Authenticator (${user.userId})`
        );
        onLoginSuccess(user, permissions);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Google Authenticator verification failed.';
        setErrorBanner(message);
        onShowToast('error', '2FA Code Rejected', message);
      } finally {
        setLoading(false);
      }
      return;
    }

    // Express backend Step 3 verification (SMS OTP or Google Authenticator TOTP)
    const codeToVerify = active2faMethod === 'TOTP' ? totpCode.trim() : otpCode.trim();
    if (!/^\d{6}$/.test(codeToVerify)) {
      setErrorBanner(
        active2faMethod === 'TOTP'
          ? 'Enter your 6-digit Google Authenticator code.'
          : 'Enter the 6-digit SMS OTP code.'
      );
      return;
    }

    setLoading(true);
    try {
      const res = await securityRequest<{
        user: Omit<UserProfile, 'avatarInitials'>;
        permissions: Record<string, boolean>;
        csrfToken: string;
        passwordExpired?: boolean;
        session?: {
          id: string;
          expiresAt: string;
          rememberMe?: boolean;
        };
        device?: {
          deviceId: string;
          deviceName: string;
          verificationStatus: string;
          isNewDevice: boolean;
        };
      }>('/api/auth/verify-otp', {
        method: 'POST',
        body: JSON.stringify({
          challengeId: otpChallengeId,
          otp: codeToVerify,
          method: active2faMethod,
        }),
      });

      setCsrfToken(res.data.csrfToken);
      const initials = res.data.user.fullName
        .split(' ')
        .map((p) => p[0])
        .slice(0, 2)
        .join('')
        .toUpperCase();

      if (res.data.passwordExpired) {
        onShowToast(
          'info',
          'Password Expiry Notice',
          'Your password is over 90 days old. Please update it in My Profile.'
        );
      } else if (res.data.device?.isNewDevice) {
        onShowToast(
          'info',
          'New Device Sign-In Recorded',
          `Verify ${res.data.device.deviceName} in Device Monitoring.`
        );
      } else {
        onShowToast(
          'success',
          `Signed in as ${res.data.user.role}`,
          `Verified via ${active2faMethod === 'TOTP' ? 'Google Authenticator' : 'SMS OTP'} (${res.data.user.userId})`
        );
      }
      onLoginSuccess(
        {
          ...res.data.user,
          avatarInitials: initials || 'MC',
        },
        res.data.permissions,
        res.data.session
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : '2FA verification failed.';
      setErrorBanner(message);
      onShowToast('error', 'Verification Rejected', message);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    if (authMode !== 'express' || !otpChallengeId) return;
    setErrorBanner(null);
    try {
      const res = await securityRequest<{
        challengeId: string;
        resendCooldownSeconds: number;
        providerConfigured: boolean;
        deliveryDetail?: string;
        sandboxOtpPreview?: string;
      }>('/api/auth/resend-otp', {
        method: 'POST',
        body: JSON.stringify({ challengeId: otpChallengeId, channel: otpChannel }),
      });
      setResendCooldown(res.data.resendCooldownSeconds);
      setProviderConfigured(res.data.providerConfigured);
      if (res.data.deliveryDetail) setOtpDeliveryDetail(res.data.deliveryDetail);
      setSandboxOtp(res.data.sandboxOtpPreview ?? null);
      onShowToast('info', 'SMS OTP Re-issued', 'A fresh 6-digit SMS verification code has been generated.');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Resend failed.';
      setErrorBanner(message);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorBanner(null);
    if (!resetUserId.trim()) {
      setErrorBanner('Enter your User ID.');
      return;
    }

    setLoading(true);
    try {
      const res = await securityRequest<{
        challengeId: string;
        maskedMobile: string;
        providerConfigured: boolean;
        sandboxOtpPreview?: string;
      }>('/api/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ userId: resetUserId.trim() }),
      });

      setResetChallengeId(res.data.challengeId);
      setOtpMaskedMobile(res.data.maskedMobile);
      setProviderConfigured(res.data.providerConfigured);
      setSandboxOtp(res.data.sandboxOtpPreview ?? null);
      setStep('reset-password');
      onShowToast('info', 'Reset OTP Issued', 'Enter the reset OTP and choose a new password.');
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Unable to initiate reset.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorBanner(null);
    setLoading(true);
    try {
      await securityRequest('/api/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({
          challengeId: resetChallengeId,
          otp: resetOtp.trim(),
          newPassword,
          confirmPassword: confirmNewPassword,
        }),
      });
      onShowToast('success', 'Password Reset Complete', 'Sign in with your new password.');
      setUserId(resetUserId);
      setPassword('');
      setStep('login');
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Password reset failed.');
    } finally {
      setLoading(false);
    }
  };

  const currentFlowStepNumber =
    step === 'login' ? 1 : step === 'validating' ? 2 : step === 'otp-verify' ? 3 : 0;

  return (
    <div className="min-h-screen bg-white dark:bg-neutral-950 text-neutral-950 dark:text-neutral-100 flex flex-col justify-between px-4 py-8">
      <div className="max-w-md w-full mx-auto my-auto">
        <div className="mb-6 text-center">
          <div className="inline-flex justify-center">
            <BrandLogo size="lg" />
          </div>
        </div>

        <div className="bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg p-6 sm:p-7">
          {/* 3-Step Authentication Progress Bar */}
          {currentFlowStepNumber > 0 && (
            <div className="mb-6 pb-4 border-b border-neutral-200 dark:border-neutral-800">
              <div className="grid grid-cols-3 gap-2">
                {[
                  { num: 1, label: 'Credentials' },
                  { num: 2, label: 'Validation' },
                  { num: 3, label: '2FA Verify' },
                ].map((item) => {
                  const isActive = currentFlowStepNumber === item.num;
                  const isCompleted = currentFlowStepNumber > item.num;
                  return (
                    <div
                      key={item.num}
                      className={`px-2.5 py-2 rounded-md border text-center transition-colors ${
                        isActive
                          ? 'bg-blue-50 dark:bg-blue-950/40 border-blue-600 text-blue-900 dark:text-blue-200'
                          : isCompleted
                            ? 'bg-green-50 dark:bg-green-950/30 border-green-600/50 text-green-800 dark:text-green-300'
                            : 'bg-neutral-50 dark:bg-neutral-950 border-neutral-200 dark:border-neutral-800 text-neutral-500 dark:text-neutral-400'
                      }`}
                    >
                      <div className="flex items-center justify-center gap-1 text-[11px] font-mono font-semibold">
                        {isCompleted ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-600 dark:text-green-400" />
                        ) : (
                          <span>Step {item.num}</span>
                        )}
                      </div>
                      <div className="text-[11px] font-medium mt-0.5 truncate">{item.label}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {errorBanner && (
            <div
              role="alert"
              className="mb-4 px-3.5 py-2.5 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 rounded-md text-xs text-red-700 dark:text-red-300"
            >
              {errorBanner}
            </div>
          )}

          {/* STEP 1: CREDENTIALS + CAPTCHA + SMS CHANNEL */}
          {step === 'login' && (
            <>
              <div className="mb-5 text-center">
                <h1 className="text-xl font-bold text-neutral-950 dark:text-white">
                  Sign in to MUN COMPUTER
                </h1>
                <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                  www.muncomputer.org · Master Admin &amp; Manager Portal
                </p>
              </div>

              {/* Direct Firebase Google Sign-In Button */}
              <div className="mb-6">
                <Button
                  type="button"
                  variant="primary"
                  size="lg"
                  loading={firebaseLoading}
                  onClick={handleFirebaseGoogleSignIn}
                  className="w-full flex items-center justify-center gap-3 bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-lg shadow-sm transition-colors cursor-pointer"
                >
                  <svg className="h-5 w-5 bg-white rounded-full p-0.5 shrink-0" viewBox="0 0 24 24">
                    <path
                      fill="#4285F4"
                      d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.13 0-5.78-2.11-6.73-4.96H1.19v3.15C3.21 21.34 7.28 24 12 24z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.27 14.24c-.25-.72-.38-1.49-.38-2.24s.13-1.52.38-2.24V6.61H1.19C.43 8.13 0 9.85 0 11.6s.43 3.47 1.19 4.99l4.08-2.35z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.28 0 3.21 2.66 1.19 6.61l4.08 3.15c.95-2.85 3.6-4.96 6.73-4.96z"
                    />
                  </svg>
                  <span>Sign in with Google (Firebase)</span>
                </Button>
              </div>

              <div className="relative my-6 text-center">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-neutral-200 dark:border-neutral-800" />
                </div>
                <div className="relative inline-block px-3 bg-white dark:bg-neutral-900 text-xs text-neutral-400">
                  Or sign in with User ID
                </div>
              </div>

              <form onSubmit={handleLoginSubmit} className="space-y-4" noValidate>
                <div>
                  <label htmlFor="auth-userid" className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5">
                    User ID
                  </label>
                  <div className="relative">
                    <User className="h-4 w-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                      id="auth-userid"
                      type="text"
                      value={userId}
                      onChange={(e) => setUserId(e.target.value)}
                      placeholder="MC2627110001"
                      className="w-full h-10 pl-9 pr-3 text-sm font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label htmlFor="auth-password" className="block text-xs font-medium text-neutral-800 dark:text-neutral-200">
                      Password
                    </label>
                    <button
                      type="button"
                      onClick={() => {
                        setErrorBanner(null);
                        setResetUserId(userId);
                        setStep('forgot-password');
                      }}
                      className="text-xs text-blue-800 dark:text-blue-400 hover:underline cursor-pointer"
                    >
                      Forgot Password?
                    </button>
                  </div>
                  <div className="relative">
                    <Lock className="h-4 w-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                      id="auth-password"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter password"
                      className="w-full h-10 pl-9 pr-10 text-sm bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((prev) => !prev)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-neutral-400 hover:text-neutral-800 dark:hover:text-white cursor-pointer"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* CAPTCHA Verification */}
                <div>
                  <label htmlFor="auth-captcha" className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5">
                    CAPTCHA Verification
                  </label>
                  <div className="flex items-center gap-2">
                    <div
                      data-testid="captcha-preview"
                      className="shrink-0 w-[144px] h-[40px] bg-[#fafafa] flex items-center justify-center rounded overflow-hidden border border-neutral-200 dark:border-neutral-700 select-none"
                      dangerouslySetInnerHTML={{ __html: captchaSvg }}
                    />
                    <button
                      type="button"
                      onClick={() => loadCaptcha(true, true)}
                      aria-label="Refresh CAPTCHA"
                      title="Refresh CAPTCHA"
                      className="h-10 w-10 inline-flex items-center justify-center rounded-md border border-neutral-200 dark:border-neutral-700 hover:bg-neutral-50 dark:hover:bg-neutral-800 text-neutral-600 dark:text-neutral-300 cursor-pointer shrink-0"
                    >
                      <RefreshCw className="h-4 w-4" />
                    </button>
                    <input
                      id="auth-captcha"
                      type="text"
                      maxLength={5}
                      autoComplete="off"
                      spellCheck={false}
                      value={captchaAnswer}
                      onChange={(e) => setCaptchaAnswer(e.target.value.toUpperCase())}
                      placeholder="Code"
                      className="w-full h-10 px-3 text-sm font-mono uppercase bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                    />
                  </div>
                </div>

                {/* Two-Factor OTP Channel: SMS Active Default Only */}
                <div>
                  <label className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5">
                    Two-Factor OTP Channel
                  </label>
                  <div className="flex items-center justify-between h-10 px-3 rounded-md border border-neutral-950 dark:border-white bg-neutral-950 dark:bg-white text-white dark:text-neutral-950">
                    <div className="flex items-center gap-2 text-xs font-mono font-semibold">
                      <MessageSquareText className="h-4 w-4" />
                      <span>SMS</span>
                    </div>
                    <span className="text-[11px] font-mono opacity-90">
                      Active Default · TOTP supported in Step 3
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <label className="inline-flex items-center gap-2 text-xs text-neutral-700 dark:text-neutral-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="h-4 w-4 rounded border-neutral-300 dark:border-neutral-700 text-neutral-950"
                    />
                    <span>Remember Me (4-hour / 240-min session)</span>
                  </label>
                </div>

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  loading={loading}
                  className="w-full"
                  icon={<ArrowRight className="h-4 w-4" />}
                >
                  Verify Credentials &amp; Send SMS OTP
                </Button>
              </form>
            </>
          )}

          {/* STEP 2: FIREBASE SDK & CREDENTIAL VALIDATION */}
          {step === 'validating' && (
            <div className="py-10 text-center space-y-4">
              <div className="inline-flex p-3 bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-400 rounded-full">
                <ShieldCheck className="h-7 w-7 animate-pulse" />
              </div>
              <div className="space-y-1">
                <h2 className="text-base font-semibold text-neutral-950 dark:text-white">
                  Validating Security Credentials
                </h2>
                <p className="text-xs text-neutral-500 dark:text-neutral-400 max-w-xs mx-auto">
                  {validationStatusText}
                </p>
              </div>
            </div>
          )}

          {/* STEP 3: 2FA VERIFICATION (SMS OTP + GOOGLE AUTHENTICATOR TOTP) */}
          {step === 'otp-verify' && (
            <>
              <div className="mb-4">
                <button
                  type="button"
                  onClick={handleBackToLogin}
                  className="inline-flex items-center gap-1 text-xs text-neutral-500 dark:text-neutral-400 hover:text-neutral-950 dark:hover:text-white mb-3 cursor-pointer"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  <span>Back to Login</span>
                </button>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-blue-800 dark:text-blue-400" />
                  <h1 className="text-lg font-semibold text-neutral-950 dark:text-white">
                    Two-Factor Verification
                  </h1>
                </div>
                <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                  Verify via SMS OTP or your 6-digit Google Authenticator code for{' '}
                  <span className="font-mono text-neutral-800 dark:text-neutral-200">
                    {otpMaskedMobile}
                  </span>
                  .
                </p>
                {otpDeliveryDetail && (
                  <p className="mt-1 text-[11px] font-mono text-neutral-500 dark:text-neutral-400">
                    {otpDeliveryDetail}
                  </p>
                )}
              </div>

              {/* 2FA Method Switcher: SMS OTP vs Google Authenticator (TOTP) */}
              <div className="grid grid-cols-2 gap-2 mb-4">
                <button
                  type="button"
                  onClick={() => {
                    setErrorBanner(null);
                    setActive2faMethod('SMS');
                  }}
                  className={`flex items-center justify-center gap-1.5 h-10 px-3 text-xs font-medium rounded-md border cursor-pointer transition-colors ${
                    active2faMethod === 'SMS'
                      ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-neutral-950 dark:border-white'
                      : 'bg-white dark:bg-neutral-950 text-neutral-700 dark:text-neutral-300 border-neutral-200 dark:border-neutral-700 hover:border-neutral-400'
                  }`}
                >
                  <MessageSquareText className="h-3.5 w-3.5" />
                  <span>SMS OTP</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setErrorBanner(null);
                    setActive2faMethod('TOTP');
                  }}
                  className={`flex items-center justify-center gap-1.5 h-10 px-3 text-xs font-medium rounded-md border cursor-pointer transition-colors ${
                    active2faMethod === 'TOTP'
                      ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-neutral-950 dark:border-white'
                      : 'bg-white dark:bg-neutral-950 text-neutral-700 dark:text-neutral-300 border-neutral-200 dark:border-neutral-700 hover:border-neutral-400'
                  }`}
                >
                  <Smartphone className="h-3.5 w-3.5" />
                  <span>Google Auth (TOTP)</span>
                </button>
              </div>

              {active2faMethod === 'SMS' && !providerConfigured && sandboxOtp && (
                <div className="mb-4 p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded-md text-xs">
                  <div className="font-semibold text-neutral-900 dark:text-white">
                    Sandbox SMS OTP Preview (SMS Provider Not Configured)
                  </div>
                  <p className="mt-1 text-neutral-600 dark:text-neutral-300">
                    Configure SMS in Master Settings → API Integrations for live dispatch. Test OTP:{' '}
                    <button
                      type="button"
                      onClick={() => setOtpCode(sandboxOtp)}
                      className="font-mono font-bold text-blue-800 dark:text-blue-400 underline cursor-pointer"
                    >
                      {sandboxOtp}
                    </button>
                  </p>
                </div>
              )}

              <form onSubmit={handleVerifyLoginOtp} className="space-y-4">
                {active2faMethod === 'SMS' ? (
                  <>
                    {authMode === 'firebase' ? (
                      <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 rounded-md text-xs text-amber-800 dark:text-amber-200">
                        Express SMS gateway is offline in direct Firebase mode. Switch to{' '}
                        <button
                          type="button"
                          onClick={() => setActive2faMethod('TOTP')}
                          className="font-semibold underline cursor-pointer"
                        >
                          Google Auth (TOTP)
                        </button>{' '}
                        to enter your 6-digit authenticator code.
                      </div>
                    ) : (
                      <div>
                        <label
                          htmlFor="login-otp"
                          className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5"
                        >
                          6-Digit SMS OTP Code
                        </label>
                        <input
                          id="login-otp"
                          type="text"
                          maxLength={6}
                          value={otpCode}
                          onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                          className="w-full h-11 px-3 text-center text-lg tracking-[0.4em] font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                        />
                      </div>
                    )}
                  </>
                ) : (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label
                        htmlFor="login-totp"
                        className="block text-xs font-medium text-neutral-800 dark:text-neutral-200"
                      >
                        6-Digit Google Authenticator / TOTP Code
                      </label>
                      <span
                        className={`text-[11px] font-mono font-semibold ${
                          totpAvailable
                            ? 'text-green-700 dark:text-green-400'
                            : 'text-amber-600 dark:text-amber-400'
                        }`}
                      >
                        {totpAvailable ? 'TOTP Linked' : 'Not Linked Yet'}
                      </span>
                    </div>
                    <input
                      id="login-totp"
                      type="text"
                      maxLength={6}
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                      placeholder="000000"
                      className="w-full h-11 px-3 text-center text-lg tracking-[0.4em] font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                    />
                    {!totpAvailable && (
                      <p className="text-[11px] text-neutral-500 dark:text-neutral-400">
                        Admin/Manager accounts can link Google Authenticator in Master Settings → Security Settings.
                      </p>
                    )}
                  </div>
                )}

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  loading={loading}
                  className="w-full"
                >
                  {active2faMethod === 'TOTP'
                    ? 'Verify Google Authenticator & Enter Dashboard'
                    : 'Verify SMS OTP & Enter Dashboard'}
                </Button>

                {active2faMethod === 'SMS' && authMode === 'express' && (
                  <div className="flex items-center justify-between text-xs pt-1">
                    <span className="text-neutral-500">Expires in 5 minutes</span>
                    <button
                      type="button"
                      disabled={resendCooldown > 0}
                      onClick={handleResendOtp}
                      className="font-medium text-blue-800 dark:text-blue-400 hover:underline disabled:text-neutral-400 disabled:no-underline cursor-pointer"
                    >
                      {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend SMS OTP'}
                    </button>
                  </div>
                )}
              </form>
            </>
          )}

          {/* FORGOT PASSWORD PAGE */}
          {step === 'forgot-password' && (
            <>
              <button
                type="button"
                onClick={() => setStep('login')}
                className="inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-950 dark:hover:text-white mb-3 cursor-pointer"
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                <span>Back to Login</span>
              </button>
              <div className="flex items-center gap-2 mb-1">
                <KeyRound className="h-5 w-5 text-blue-800 dark:text-blue-400" />
                <h1 className="text-lg font-semibold text-neutral-950 dark:text-white">
                  Forgot Password
                </h1>
              </div>
              <p className="text-xs text-neutral-500 dark:text-neutral-400 mb-5">
                Enter your MUN COMPUTER User ID to receive a password reset SMS OTP.
              </p>

              <form onSubmit={handleForgotPasswordSubmit} className="space-y-4">
                <div>
                  <label htmlFor="fp-userid" className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5">
                    User ID
                  </label>
                  <input
                    id="fp-userid"
                    type="text"
                    value={resetUserId}
                    onChange={(e) => setResetUserId(e.target.value)}
                    placeholder="MC2627110001"
                    className="w-full h-10 px-3 text-sm font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md focus:outline-none focus:border-blue-800"
                  />
                </div>
                <Button type="submit" variant="primary" size="lg" loading={loading} className="w-full">
                  Send Password Reset OTP
                </Button>
              </form>
            </>
          )}

          {/* PASSWORD RESET PAGE */}
          {step === 'reset-password' && (
            <>
              <button
                type="button"
                onClick={() => setStep('forgot-password')}
                className="inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-950 dark:hover:text-white mb-3 cursor-pointer"
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                <span>Back</span>
              </button>
              <h1 className="text-lg font-semibold text-neutral-950 dark:text-white">Reset Password</h1>
              <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400 mb-4">
                Verify reset OTP sent to {otpMaskedMobile}. Existing sessions will be revoked.
              </p>

              {!providerConfigured && sandboxOtp && (
                <div className="mb-4 p-3 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded-md text-xs">
                  Sandbox Reset OTP:{' '}
                  <button
                    type="button"
                    onClick={() => setResetOtp(sandboxOtp)}
                    className="font-mono font-bold text-blue-800 dark:text-blue-400 underline cursor-pointer"
                  >
                    {sandboxOtp}
                  </button>
                </div>
              )}

              <form onSubmit={handleResetPasswordSubmit} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1">
                    Reset OTP
                  </label>
                  <input
                    type="text"
                    maxLength={6}
                    value={resetOtp}
                    onChange={(e) => setResetOtp(e.target.value.replace(/\D/g, ''))}
                    placeholder="6-digit OTP"
                    className="w-full h-10 px-3 text-sm font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1">
                    New Strong Password (12+ chars, upper/lower/num/special)
                  </label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full h-10 px-3 text-sm bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1">
                    Confirm Password
                  </label>
                  <input
                    type="password"
                    value={confirmNewPassword}
                    onChange={(e) => setConfirmNewPassword(e.target.value)}
                    className="w-full h-10 px-3 text-sm bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-md"
                  />
                </div>
                <Button type="submit" variant="primary" size="lg" loading={loading} className="w-full">
                  Reset Password
                </Button>
              </form>
            </>
          )}
        </div>
      </div>

      <footer className="text-center text-xs text-neutral-500 pt-6">
        {BRAND.copyright} · Version {BRAND.version}
      </footer>
    </div>
  );
};
