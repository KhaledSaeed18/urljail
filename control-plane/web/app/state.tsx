// Run state as a pill: state is encoded in form, not only text.
export function StatePill({ state, consistent }: { state: string; consistent?: boolean }) {
  const cls = state === 'done' ? (consistent === false ? 'warn' : 'ok') : state === 'failed' ? 'bad' : '';
  return <span className={`pill ${cls}`}>{state === 'done' && consistent === false ? 'done · host≠guest' : state}</span>;
}

export const when = (s: string | null) => (s ? new Date(s).toLocaleString('en-GB', { hour12: false }) : '–');
