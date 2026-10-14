import Link from 'next/link';
import { api } from '@/lib/api';

export const dynamic = 'force-dynamic';

const pct = (n: number, of: number) => (of ? `${Math.round((100 * n) / of)} %` : '–');

// The indicators against the labels. URLs and notes are shown as text, never linked.
export default async function Evaluate() {
  const e = await api.evaluation();
  return (
    <>
      <header className="top">
        <h1><Link href="/">urljail</Link> / indicators vs labels</h1>
        <span className="muted mono">{e.phish} phishing · {e.other} not phishing · {e.unsure} unsure (left out)</span>
        <a href="/labels.tsv" download>Download labels (TSV)</a>
      </header>

      <section className="card">
        <p className="muted" style={{ marginTop: 0 }}>
          Every labelled run, scored with the indicators its stored report has. That includes the runs the rules were tuned on, so this
          overstates how they do on new pages; the held-out results are in the P7 journal.
          {' '}<Link href="/?view=unlabelled">Label more runs</Link>.
        </p>
        <h2>By severity</h2>
        <div className="table"><table>
          <thead><tr><th>Flagged at</th><th className="num">Phishing flagged</th><th className="num">Not phishing flagged</th></tr></thead>
          <tbody>{e.thresholds.map((t) => (
            <tr key={t.name}><td>{t.name}</td><td className="num">{t.flaggedPhish} of {e.phish} ({pct(t.flaggedPhish, e.phish)})</td><td className="num">{t.flaggedOther} of {e.other}</td></tr>
          ))}</tbody>
        </table></div>
      </section>

      <div className="grid2">
        <section className="card">
          <h2>By indicator</h2>
          <div className="table"><table>
            <thead><tr><th>Indicator</th><th className="num">Phishing</th><th className="num">Not phishing</th></tr></thead>
            <tbody>{e.indicators.map((i) => (
              <tr key={i.id}><td className="mono"><Link href={`/?indicator=${encodeURIComponent(i.id)}`}>{i.id}</Link></td><td className="num">{i.flaggedPhish}</td><td className="num">{i.flaggedOther}</td></tr>
            ))}</tbody>
          </table></div>
        </section>
        <section className="card">
          <h2>By kind of phishing (medium and up)</h2>
          <div className="table"><table>
            <thead><tr><th>Kind</th><th className="num">Flagged</th></tr></thead>
            <tbody>{e.byKind.map((k) => (
              <tr key={k.kind}><td>{k.kind}</td><td className="num">{k.flagged} of {k.phish}</td></tr>
            ))}</tbody>
          </table></div>
        </section>
      </div>

      <section className="card">
        <h2>Flagged, but not phishing ({e.falsePositives.length})</h2>
        <div className="table"><table>
          <thead><tr><th>Run</th><th>Label</th><th>Indicators</th><th>Note</th></tr></thead>
          <tbody>{e.falsePositives.map((f) => (
            <tr key={f.id}><td className="urlcell"><Link href={`/runs/${f.id}`}><span className="url">{f.url}</span></Link></td><td>{f.verdict}</td><td className="mono">{f.indicators.join(' ')}</td><td>{f.note}</td></tr>
          ))}</tbody>
        </table></div>
      </section>

      <section className="card">
        <h2>Phishing nothing flagged at medium or up ({e.missed.length})</h2>
        <div className="table"><table>
          <thead><tr><th>Run</th><th>Kind</th><th>Brand</th><th>Note</th></tr></thead>
          <tbody>{e.missed.map((m) => (
            <tr key={m.id}><td className="urlcell"><Link href={`/runs/${m.id}`}><span className="url">{m.url}</span></Link></td><td>{m.kind}</td><td>{m.brand}</td><td>{m.note}</td></tr>
          ))}</tbody>
        </table></div>
      </section>
    </>
  );
}
