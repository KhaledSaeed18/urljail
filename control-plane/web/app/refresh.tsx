'use client';
// Re-renders the page every 2 s while something is still running.
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export function Refresh({ while: on }: { while: boolean }) {
  const router = useRouter();
  useEffect(() => {
    if (!on) return;
    const t = setInterval(() => router.refresh(), 2000);
    return () => clearInterval(t);
  }, [on, router]);
  return null;
}
