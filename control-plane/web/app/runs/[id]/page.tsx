import Link from 'next/link';
import { notFound } from 'next/navigation';
import { api, active } from '@/lib/api';
import { Refresh } from '../../refresh';
import { StatePill, when } from '../../state';
import { NetworkGraph } from './graph';
import { saveLabel } from '../../actions';

export const dynamic = 'force-dynamic';

// Everything from `report` is attacker-influenced: rendered as text only, URLs never linked.
// Field names are the proto names (report.json is written with UseProtoNames).
export default async function Run({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const { id } = await params;
  const q = await searchParams;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const run = await api.get(id).catch(() => null);
  if (!run) notFound();
  // Blind labelling (the review queue): no indicators or look-alikes until the run is labelled,
  // so a label can't lean on what the rules said.
  const blind = q.blind === '1' && !run.label;
  const rep = run.report ?? {};
  const nav = rep.navigation ?? {};
  const net = rep.network ?? {};
  const rec = rep.reconciliation ?? {};
  const chain: any[] = nav.redirect_chain ?? [];
  const domains: any[] = net.domains ?? [];
  const unexplained: string[] = [...(rec.unexplained_flows ?? []), ...(rec.unexplained_dns ?? []).map((d: string) => `dns ${d}`), ...(rec.guest_only_requests ?? []).map((u: string) => `guest-only ${u}`)];
  const finalHost = hostOf(nav.final_url);
  const pageDomain = domains.find((d) => (d.hosts ?? []).includes(finalHost))?.registrable ?? '';
  const counted = countRequests(domains, net.requests ?? []);
  const indicators: any[] = rep.indicators ?? [];
  const forms: any[] = rep.page?.forms ?? [];
  const similar = run.summary?.phash && !(q.blind === '1' && !run.label) ? await api.similar(id).catch(() => null) : null;
  return (
    <>
      <header className="top">
        <h1><Link href="/">urljail</Link> / run</h1>
        <StatePill state={run.state} consistent={run.summary?.consistent} />
        <span className="muted mono">{when(run.createdAt)} · {run.profile || 'default profile'}{run.runId ? ` · ${run.runId}` : ''}</span>
      </header>

      <section className="card">
        <dl className="kv">
          <dt>Submitted</dt><dd className="url">{run.url}</dd>
          <dt>Final URL</dt><dd className="url">{nav.final_url || '–'}</dd>
          <dt>Title</dt><dd>{nav.title || <span className="muted">(none)</span>}</dd>
          {nav.error && (<><dt>Navigation</dt><dd>{nav.error}</dd></>)}
          <dt>Observed</dt><dd>{nav.dwell_ms ? `${nav.dwell_ms} ms (${nav.dwell_reason})` : '–'}</dd>
          {rep.run?.feed && (<><dt>Feed</dt><dd className="mono">{rep.run.feed.name}, first seen {when(rep.run.feed.first_seen)}</dd></>)}
        </dl>
        {active(run.state) && <div className="notice">Running: {run.state}{run.message ? ` · ${run.message}` : ''}</div>}
        {run.error && <div className="error">{run.error}</div>}
      </section>

      {indicators.length > 0 && !blind && (
        <section className="card">
          <h2>Indicators</h2>
          <ul className="gaps">{indicators.map((x, i) => (
            <li key={i}><span className={`pill ${x.severity === 'high' ? 'bad' : x.severity === 'medium' ? 'warn' : ''}`}>{x.severity}</span> <span className="mono">{x.id}</span>: {x.detail}</li>
          ))}</ul>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>Signals with their reasons, not a verdict.</p>
        </section>
      )}

      {!active(run.state) && (
        <section className="card">
          <h2>Label</h2>
          <form className="label" action={saveLabel}>
            <input type="hidden" name="id" value={id} />
            {blind && <input type="hidden" name="blind" value="1" />}
            <div className="verdicts">
              {[['phish', 'Phishing'], ['benign', 'Benign'], ['unsure', 'Unsure'], ['real-site', "The brand's real site"]].map(([v, text]) => (
                <label key={v}><input type="radio" name="verdict" value={v} required defaultChecked={run.label?.verdict === v} /> {text}</label>
              ))}
            </div>
            <div className="fields">
              <select name="kind" defaultValue={run.label?.kind ?? ''} aria-label="Kind of phishing">
                <option value="">kind (phishing only)</option>
                {['credential', 'payment', 'lure', 'gate', 'device-code'].map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
              <input name="brand" defaultValue={run.label?.brand ?? ''} placeholder="brand (e.g. paypal)" pattern="[a-z0-9-]{0,40}" maxLength={40} aria-label="Brand" />
              <input name="note" defaultValue={run.label?.note ?? ''} placeholder="note: what the page is" maxLength={300} aria-label="Note" />
            </div>
            <div className="buttons">
              <button type="submit">Save</button>
              <button type="submit" name="next" value="1">Save and next unlabelled</button>
              {run.label && <button type="submit" name="clear" value="1" formNoValidate className="secondary">Clear label</button>}
              {run.label?.labelledAt && <span className="muted" style={{ fontSize: 13 }}>labelled {when(run.label.labelledAt)}</span>}
            </div>
          </form>
        </section>
      )}

      <div className="grid2">
        <section className="card">
          <h2>Screenshot</h2>
          {rep.artifacts?.screenshot ? <img className="shot" src={`/runs/${id}/screenshot`} alt="Screenshot of the final page (taken in the VM)" /> : <p className="muted">No screenshot.</p>}
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>Guest-attested: produced inside the VM the page ran in.</p>
        </section>
        <section className="card">
          <h2>Network</h2>
          <NetworkGraph domains={counted} page={pageDomain} />
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            {(net.requests ?? []).length} requests, {(net.flows ?? []).length} host-observed flows, {(net.blocked ?? []).length} blocked destinations
            {rep.artifacts?.har && <> · <a href={`/runs/${id}/har`} download>Download HAR</a></>}
          </p>
        </section>
      </div>

      <section className="card">
        <h2>Redirect chain</h2>
        {chain.length === 0 ? <p className="muted">No navigation recorded.</p> : (
          <div className="table"><table>
            <thead><tr><th className="num">#</th><th>Kind</th><th className="num">Status</th><th>URL</th></tr></thead>
            <tbody>{chain.map((h, i) => (
              <tr key={i}><td className="num">{i + 1}</td><td className="mono">{h.kind}</td><td className="num">{h.status ?? ''}</td><td><span className="url">{h.url}</span></td></tr>
            ))}</tbody>
          </table></div>
        )}
      </section>

      {(forms.length > 0 || rep.page?.password_fields > 0) && (
        <section className="card">
          <h2>Forms</h2>
          <p className="muted" style={{ marginTop: 0 }}>{rep.page?.password_fields ?? 0} password field(s) on the page; forms in the top document only.</p>
          {forms.length > 0 && (
            <div className="table"><table>
              <thead><tr><th>Method</th><th>Sends to</th><th>Fields</th></tr></thead>
              <tbody>{forms.slice(0, 32).map((f, i) => (
                <tr key={i}>
                  <td className="mono">{f.method}</td>
                  <td><span className="url">{f.action}</span>{f.cross_origin_action && <> <span className="pill warn">other domain</span></>}</td>
                  <td className="mono">{(f.fields ?? []).slice(0, 64).map((x: any) => `${x.name || '?'}:${x.type}`).join(' ')}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </section>
      )}

      {blind ? (
        <section className="card"><p className="muted" style={{ margin: 0 }}>Blind labelling: indicators and look-alike runs stay hidden until this run is labelled.</p></section>
      ) : (
      <section className="card">
        <h2>Looks like</h2>
        {!run.summary?.phash ? <p className="muted" style={{ margin: 0 }}>{rep.page?.screenshot_blank ? 'The screenshot is blank.' : 'No screenshot hash.'}</p>
          : !similar || similar.runs.length === 0 ? <p className="muted" style={{ margin: 0 }}>No other run's screenshot is within {similar?.maxDistance ?? 6} of 64 bits (hash <span className="mono">{run.summary.phash}</span>).</p> : (
          <div className="table"><table>
            <thead><tr><th className="num">Bits apart</th><th>Run</th><th>Final URL</th><th>Title</th></tr></thead>
            <tbody>{similar.runs.slice(0, 50).map((r) => (
              <tr key={r.id}>
                <td className="num">{r.distance}</td>
                <td className="mono"><Link href={`/runs/${r.id}`}>{when(r.createdAt)}</Link></td>
                <td className="urlcell"><span className="url">{r.summary?.finalUrl || r.url}</span></td>
                <td>{r.summary?.title ?? ''}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </section>
      )}

      <section className="card">
        <h2>Host vs guest</h2>
        {rec.consistent ? <p style={{ margin: 0 }}><span className="pill ok">consistent</span> Everything the host saw on the wire is explained by what the guest reported.</p> : (
          <>
            <p style={{ margin: 0 }}><span className="pill warn">not consistent</span> The host saw traffic the guest didn't report, or the reverse:</p>
            <ul className="gaps">{unexplained.slice(0, 50).map((u, i) => <li key={i} className="url">{u}</li>)}</ul>
          </>
        )}
      </section>

      {(rep.gaps ?? []).length > 0 && (
        <section className="card">
          <h2>What this report can't tell you</h2>
          <ul className="gaps">{(rep.gaps as string[]).map((g, i) => <li key={i}>{g}</li>)}</ul>
        </section>
      )}
      <Refresh while={active(run.state)} />
    </>
  );
}

function hostOf(u: unknown): string {
  try {
    return new URL(String(u)).hostname;
  } catch {
    return '';
  }
}

// Requests per registrable domain, from the request list (Domain carries hosts, not counts).
function countRequests(domains: any[], requests: any[]) {
  const byHost = new Map<string, number>();
  for (const r of requests) {
    const h = hostOf(r?.url);
    if (h) byHost.set(h, (byHost.get(h) ?? 0) + 1);
  }
  return domains.map((d) => ({
    registrable: String(d?.registrable ?? ''),
    requests: (Array.isArray(d?.hosts) ? d.hosts : []).reduce((n: number, h: string) => n + (byHost.get(h) ?? 0), 0),
  }));
}
