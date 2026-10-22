// TypeScript / ES-module fixtures for rules_staging/javascript_weakness.yaml (Pass N3, staged).
import session from 'express-session';
import express, { Request, Response } from 'express';

const app = express();

// ruleid: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

// ruleid: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { maxAge: 3600000 } }));

// ruleid: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: true, httpOnly: false } }));

// ok: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));

// ok: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: app.get('env') === 'production' } }));

const cookieConfig = { secure: true, httpOnly: true };
// options held in a variable are not inspected
// ok: aegis-js-insecure-session-cookie-esm
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: cookieConfig }));

export function issue(req: Request, res: Response): void {
  const inviteCode: string = Math.random().toString(36).slice(2, 10);
  const jitterMs: number = Math.random() * 250;
  res.cookie('jwt', inviteCode, { secure: true });
  res.json({ inviteCode, jitterMs });
}
