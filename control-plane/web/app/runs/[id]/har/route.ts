// The run's HAR, proxied from the API with the token kept here; always a download, never shown.
import { api } from '@/lib/api';

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-f-]{36}$/.test(id)) return new Response('bad id', { status: 400 });
  const r = await api.har(id);
  if (!r.ok) return new Response('no HAR', { status: r.status });
  return new Response(await r.arrayBuffer(), {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': r.headers.get('content-disposition') ?? 'attachment; filename="urljail.har"',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, no-store',
    },
  });
}
