// TypeScript / ES-module fixtures for rules/taint/javascript_weakness.yaml (Pass N3).
import session from 'express-session';
import express, { Request, Response } from 'express';

const app = express();

app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { maxAge: 3600000 } }));

app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: true, httpOnly: false } }));

app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));

app.use(session({ secret: process.env.SESSION_SECRET!, cookie: { secure: app.get('env') === 'production' } }));

const cookieConfig = { secure: true, httpOnly: true };
// options held in a variable are not inspected
app.use(session({ secret: process.env.SESSION_SECRET!, cookie: cookieConfig }));

export function issue(req: Request, res: Response): void {
  // ruleid: aegis-js-weak-random-secret
  const inviteCode: string = Math.random().toString(36).slice(2, 10);
  // ok: aegis-js-weak-random-secret
  const jitterMs: number = Math.random() * 250;
  // ruleid: aegis-js-insecure-session-cookie
  res.cookie('jwt', inviteCode, { secure: true });
  res.json({ inviteCode, jitterMs });
}
