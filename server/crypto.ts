import crypto from 'node:crypto';

const SERVER_SECRET =
  process.env.JWT_SECRET ||
  crypto
    .createHash('sha256')
    .update('mun-computer-phase02-dev-secret-key')
    .digest('hex');

const AES_KEY = crypto
  .createHash('sha256')
  .update(SERVER_SECRET + ':aadhaar-aes-256')
  .digest();

/**
 * Memory-hard scrypt password hashing with random 16-byte salt (never plaintext).
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$${salt}$${derived.toString('hex')}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const salt = parts[2];
  const expectedHex = parts[3];
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

/**
 * AES-256-GCM authenticated encryption for optional Aadhaar numbers.
 */
export function encryptSensitiveField(plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptSensitiveField(payload: string): string {
  const [ivHex, tagHex, dataHex] = payload.split(':');
  if (!ivHex || !tagHex || !dataHex) {
    throw new Error('Malformed encrypted payload');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    AES_KEY,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function maskAadhaar(last4?: string): string {
  if (!last4) return 'Not Provided';
  return `XXXX-XXXX-${last4}`;
}

export function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hmacOtp(otp: string, challengeId: string): string {
  return crypto
    .createHmac('sha256', SERVER_SECRET)
    .update(`${challengeId}:${otp}`)
    .digest('hex');
}

export function generateNumericOtp(digits = 6): string {
  const min = 10 ** (digits - 1);
  const max = 10 ** digits;
  return String(crypto.randomInt(min, max));
}

export function generateToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function generateCaptchaChallenge(): {
  id: string;
  answerHash: string;
  svg: string;
  questionHint: string;
} {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 5; i += 1) {
    code += chars[crypto.randomInt(0, chars.length)];
  }
  const id = generateToken(12);
  const answerHash = hmacOtp(code.toUpperCase(), id);

  const svgLetters = code
    .split('')
    .map((ch, idx) => {
      const x = 18 + idx * 24;
      const y = 26 + (idx % 2 === 0 ? -2 : 3);
      const rot = idx % 2 === 0 ? -8 : 7;
      return `<text x="${x}" y="${y}" transform="rotate(${rot} ${x} ${y})" font-family="monospace" font-size="20" font-weight="700" fill="#0a0a0a">${ch}</text>`;
    })
    .join('');

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="144" height="40" viewBox="0 0 144 40" role="img" aria-label="Security verification code">
    <rect width="144" height="40" rx="4" fill="#fafafa" stroke="#e5e5e5"/>
    <line x1="8" y1="14" x2="136" y2="28" stroke="#d4d4d8" stroke-width="1"/>
    <line x1="12" y1="30" x2="132" y2="11" stroke="#cbd5e1" stroke-width="1"/>
    ${svgLetters}
  </svg>`;

  return {
    id,
    answerHash,
    svg,
    questionHint: 'Enter the 5-character code',
  };
}

export function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  cookieHeader.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      out[key] = decodeURIComponent(val);
    }
  });
  return out;
}

export function sanitizeText(value: string): string {
  return value.replace(/[<>]/g, '').trim();
}
