// Every label with the run's indicators, proxied from the API; a download.
import { api } from '@/lib/api';

export async function GET() {
  const r = await api.labelsTsv();
  if (!r.ok) return new Response('no labels', { status: r.status });
  return new Response(await r.arrayBuffer(), {
    headers: {
      'Content-Type': 'text/tab-separated-values; charset=utf-8',
      'Content-Disposition': 'attachment; filename="urljail-labels.tsv"',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, no-store',
    },
  });
}
