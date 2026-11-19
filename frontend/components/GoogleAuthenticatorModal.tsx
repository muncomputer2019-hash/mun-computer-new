import React, { useState, useEffect } from 'react';
import { ShieldCheck, QrCode, CheckCircle2, AlertCircle, X, Copy, Check } from 'lucide-react';
import * as OTPAuth from 'otpauth';
import { Button } from './Button';
import { securityRequest } from '../services/securityApi';

interface GoogleAuthenticatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  userEmail: string;
  userId: string;
  onShowToast: (type: 'success' | 'error' | 'info', title: string, description?: string) => void;
  onSuccess?: () => void;
}

export const GoogleAuthenticatorModal: React.FC<GoogleAuthenticatorModalProps> = ({
  isOpen,
  onClose,
  userEmail,
  userId,
  onShowToast,
  onSuccess,
}) => {
  const [secret, setSecret] = useState<string>('');
  const [totpUri, setTotpUri] = useState<string>('');
  const [verificationCode, setVerificationCode] = useState<string>('');
  const [isVerified, setIsVerified] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      const newSecret = new OTPAuth.Secret({ size: 20 });
      const base32Secret = newSecret.base32;
      setSecret(base32Secret);

      const totp = new OTPAuth.TOTP({
        issuer: 'MUN COMPUTER',
        label: userEmail || userId || 'admin@muncomputer',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: newSecret,
      });

      setTotpUri(totp.toString());
      setVerificationCode('');
      setIsVerified(false);
      setCopied(false);
      setError(null);
    }
  }, [isOpen, userEmail, userId]);

  if (!isOpen) return null;

  const handleCopySecret = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      onShowToast('info', 'Setup Key Copied', 'Paste the Base32 key into Google Authenticator.');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      onShowToast('info', 'Manual Copy', 'Select the Base32 key text to copy it manually.');
    }
  };

  const handleVerifyAndEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanCode = verificationCode.trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      setError('Please enter a valid 6-digit verification code from Google Authenticator.');
      return;
    }

    setLoading(true);
    try {
      const totp = new OTPAuth.TOTP({
        issuer: 'MUN COMPUTER',
        label: userEmail || userId,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secret),
      });

      const delta = totp.validate({ token: cleanCode, window: 1 });
      if (delta === null) {
        setError('Invalid verification code. Please check your Google Authenticator app and try again.');
        onShowToast('error', 'Verification Failed', 'Invalid 6-digit OTP code.');
        return;
      }

      await securityRequest<{ totpEnabled: boolean }>('/api/auth/totp/enable', {
        method: 'POST',
        body: JSON.stringify({ secret, code: cleanCode }),
      });

      setIsVerified(true);
      onShowToast(
        'success',
        'Google Authenticator Enabled',
        'Two-factor authentication via Google Authenticator is now saved and active.'
      );
      if (onSuccess) onSuccess();
      setTimeout(() => {
        onClose();
      }, 1400);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Verification error.';
      setError(message);
      onShowToast('error', 'Setup Failed', message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4 animate-fadeIn">
      <div className="bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-xl shadow-2xl max-w-md w-full overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-blue-100 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 rounded-lg">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-neutral-950 dark:text-white">
                Google Authenticator (2FA)
              </h2>
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                Secure your MUN COMPUTER account with TOTP
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {error && (
            <div className="p-3 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 rounded-lg text-xs text-red-700 dark:text-red-300 flex items-start gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {isVerified ? (
            <div className="py-8 text-center space-y-3">
              <div className="inline-flex p-3 bg-green-100 dark:bg-green-950/60 text-green-600 dark:text-green-400 rounded-full">
                <CheckCircle2 className="h-8 w-8" />
              </div>
              <h3 className="text-base font-semibold text-neutral-950 dark:text-white">
                Google Authenticator Successfully Linked!
              </h3>
              <p className="text-xs text-neutral-500 dark:text-neutral-400 max-w-xs mx-auto">
                Your account is now protected with time-based one-time passwords.
              </p>
            </div>
          ) : (
            <>
              <div className="space-y-2">
                <span className="text-xs font-medium text-neutral-800 dark:text-neutral-200 block">
                  Step 1: Add Setup Key in Google Authenticator
                </span>
                <p className="text-xs text-neutral-500 dark:text-neutral-400">
                  Open Google Authenticator and choose &ldquo;Enter a setup key&rdquo; (Time-based) with account{' '}
                  <span className="font-mono text-neutral-800 dark:text-neutral-200">
                    {userEmail || userId}
                  </span>
                  .
                </p>

                <div className="p-4 bg-neutral-50 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 rounded-xl text-center space-y-3">
                  <div className="inline-flex p-3 bg-white dark:bg-neutral-900 rounded-lg shadow-inner border border-neutral-200 dark:border-neutral-800">
                    <div
                      title={totpUri}
                      className="w-36 h-24 flex flex-col items-center justify-center bg-white dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 p-2 font-mono text-[10px] border border-neutral-200 dark:border-neutral-800 rounded"
                    >
                      <QrCode className="h-10 w-10 text-blue-600 dark:text-blue-400 mb-1" />
                      <span className="font-semibold">TOTP SHA1 · 30s</span>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <span className="text-[11px] text-neutral-500 block">Manual Setup Key (Base32):</span>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 font-mono text-xs font-bold text-blue-800 dark:text-blue-400 bg-white dark:bg-neutral-900 py-1.5 px-3 rounded border border-neutral-200 dark:border-neutral-800 select-all truncate">
                        {secret}
                      </div>
                      <button
                        type="button"
                        onClick={handleCopySecret}
                        className="inline-flex items-center gap-1 h-8 px-2.5 text-xs font-medium rounded border border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-900 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-200 cursor-pointer shrink-0"
                      >
                        {copied ? <Check className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                        <span>{copied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <form onSubmit={handleVerifyAndEnable} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-neutral-800 dark:text-neutral-200 mb-1.5">
                    Step 2: Enter 6-digit Code from Authenticator App
                  </label>
                  <input
                    type="text"
                    maxLength={6}
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000000"
                    className="w-full h-11 px-3 text-center text-lg tracking-[0.4em] font-mono bg-white dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-700 rounded-lg focus:outline-none focus:border-blue-600"
                  />
                </div>

                <div className="flex items-center justify-end gap-3 pt-2">
                  <Button type="button" variant="ghost" onClick={onClose}>
                    Cancel
                  </Button>
                  <Button type="submit" variant="primary" loading={loading}>
                    Verify &amp; Enable
                  </Button>
                </div>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
