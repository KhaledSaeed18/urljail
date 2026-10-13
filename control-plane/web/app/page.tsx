import Link from 'next/link';
import { api, active } from '@/lib/api';
import { submit } from './actions';
import { Refresh } from './refresh';
import { StatePill, when } from './state';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const [status, { runs }] = await Promise.all([api.status(), api.list()]);
  const d = status.daemon;
  return (
    <>
      <header className="top">
        <h1>urljail</h1>
        {d ? (
          <>
            <span className={`pill ${d.egressMode === 'live' ? 'warn' : ''}`}>egress {d.egressMode}</span>
            <span className="muted mono">urljaild {d.urljail} · {d.maxVms} VM slots</span>
          </>
        ) : (
          <span className="pill bad">daemon unreachable</span>
        )}
        <span className="muted mono">queue: {status.queue.waiting ?? 0} waiting, {status.queue.active ?? 0} running</span>
      </header>
      {status.daemonError && <div className="error">urljaild: {status.daemonError}</div>}

      <section className="card">
        <h2>Detonate a URL</h2>
        <form className="submit" action={submit}>
          <input id="url" name="url" type="text" required maxLength={2048} placeholder="https://…" autoComplete="off" spellCheck={false} aria-label="URL" />
          <select id="profile" name="profile" aria-label="Browser profile" defaultValue="">
            <option value="">default profile</option>
            {(d?.profiles ?? []).map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <button type="submit">Detonate</button>
        </form>
        {d?.egressMode === 'live' && <div className="notice">Live mode: the URL is opened through the VPN in a disposable VM. Never paste a URL that carries your own credentials or session.</div>}
      </section>

      <section className="card">
        <h2>Runs</h2>
        {runs.length === 0 ? (
          <p className="muted">No runs yet. Submit a URL above; it appears here while it runs.</p>
        ) : (
          <div className="table">
            <table>
              <thead>
                <tr><th>Submitted</th><th>State</th><th>URL</th><th>Final page</th><th className="num">Requests</th><th>Profile</th><th>Via</th></tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td><Link className="row" href={`/runs/${r.id}`}>{when(r.createdAt)}</Link></td>
                    <td><StatePill state={r.state} consistent={r.summary?.consistent} /></td>
                    <td className="urlcell"><span className="url">{r.url}</span></td>
                    <td>{r.summary ? (r.summary.navError ? <span className="muted">{r.summary.navError}</span> : r.summary.title || <span className="muted">(no title)</span>) : <span className="muted">{r.error || r.message}</span>}</td>
                    <td className="num">{r.summary?.requests ?? ''}</td>
                    <td className="mono">{r.profile || 'default'}</td>
                    <td className="muted mono">{r.source === 'cli' ? 'cli' : 'dashboard'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <Refresh while={runs.some((r) => active(r.state))} />
    </>
  );
}
