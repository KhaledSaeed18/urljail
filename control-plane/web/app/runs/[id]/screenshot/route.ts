// The screenshot, proxied from the API (which checked it is a PNG) with the token kept here.
import { api } from '@/lib/api';

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return new Response('bad id', { status: 400 });
  const r = await api.screenshot(id);
  if (!r.ok) return new Response('no screenshot', { status: r.status });
  return new Response(await r.arrayBuffer(), {
    headers: { 'Content-Type': 'image/png', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, max-age=3600', 'Content-Disposition': 'inline' },
  });
}
