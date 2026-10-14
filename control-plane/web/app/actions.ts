'use server';
// Submitting a URL: a Server Action, so Next checks that the request came from this origin.
import { redirect } from 'next/navigation';
import { api } from '@/lib/api';

export async function submit(form: FormData) {
  const url = String(form.get('url') ?? '').trim();
  const profile = String(form.get('profile') ?? '');
  const { id } = await api.submit(url, profile);
  redirect(`/runs/${id}`);
}

const UUID = /^[0-9a-f-]{36}$/;

// Labelling a run, also a Server Action (same-origin check). "next" moves on to the oldest
// unlabelled run in the review queue.
export async function saveLabel(form: FormData) {
  const id = String(form.get('id') ?? '');
  if (!UUID.test(id)) throw new Error('bad run id');
  if (form.get('clear')) {
    await api.unlabel(id);
    redirect(`/runs/${id}`);
  }
  await api.label(id, {
    verdict: String(form.get('verdict') ?? ''),
    kind: String(form.get('kind') ?? ''),
    brand: String(form.get('brand') ?? '').trim().toLowerCase(),
    note: String(form.get('note') ?? ''),
  });
  if (form.get('next')) {
    const { runs } = await api.list({ view: 'unlabelled' });
    const next = runs.filter((r) => r.id !== id).at(-1);
    if (next) redirect(`/runs/${next.id}`);
    redirect('/?view=unlabelled');
  }
  redirect(`/runs/${id}`);
}
