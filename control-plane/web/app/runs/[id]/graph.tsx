// Network graph: the page's registrable domain in the middle, every other domain it contacted
// around it, edge width by request count. Labels are text nodes (escaped), never markup.
interface Domain { registrable?: string; requests?: number; hosts?: string[] }

export function NetworkGraph({ domains, page }: { domains: Domain[]; page: string }) {
  const items = domains.filter((d) => d.registrable).slice(0, 24);
  if (items.length === 0) return <p className="muted">No requests reached the network.</p>;
  const center = items.find((d) => d.registrable === page) ?? items[0];
  const others = items.filter((d) => d !== center);
  const W = 560, H = 380, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 56;
  const max = Math.max(1, ...items.map((d) => d.requests ?? 1));
  const pts = others.map((d, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, others.length) - Math.PI / 2;
    return { d, x: cx + R * Math.cos(a), y: cy + R * Math.sin(a), a };
  });
  return (
    <svg className="graph" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Domains contacted by the page">
      {pts.map(({ d, x, y }) => (
        <line key={`l-${d.registrable}`} x1={cx} y1={cy} x2={x} y2={y} stroke="var(--rule)" strokeWidth={1 + (5 * (d.requests ?? 1)) / max} />
      ))}
      <circle cx={cx} cy={cy} r={9} fill="var(--accent)" />
      <text x={cx} y={cy - 16} textAnchor="middle">{center.registrable} ({center.requests ?? 0})</text>
      {pts.map(({ d, x, y, a }) => {
        const right = Math.cos(a) >= 0;
        return (
          <g key={`n-${d.registrable}`}>
            <circle cx={x} cy={y} r={5} fill="var(--muted)" />
            <text x={x + (right ? 9 : -9)} y={y + 4} textAnchor={right ? 'start' : 'end'}>{d.registrable} ({d.requests ?? 0})</text>
          </g>
        );
      })}
    </svg>
  );
}
