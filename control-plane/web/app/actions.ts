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
