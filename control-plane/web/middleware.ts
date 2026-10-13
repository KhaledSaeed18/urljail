// Every response: localhost only (DNS rebinding), and a CSP that allows nothing from other
// origins, so hostile report text can't load or send anything even if it were ever rendered.
import { NextResponse, type NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const host = (req.headers.get('host') ?? '').replace(/:\d+$/, '');
  if (host !== '127.0.0.1' && host !== 'localhost') {
    return new NextResponse('requests must be addressed to localhost', { status: 421 });
  }
  const res = NextResponse.next();
  res.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; " +
      "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'",
  );
  res.headers.set('X-Content-Type-Options', 'nosniff');
  res.headers.set('Referrer-Policy', 'no-referrer');
  res.headers.set('X-Frame-Options', 'DENY');
  return res;
}
