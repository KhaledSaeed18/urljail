import './globals.css';
import type { ReactNode } from 'react';

export const metadata = { title: 'urljail console', referrer: 'no-referrer' as const };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="wrap">{children}</div>
      </body>
    </html>
  );
}
