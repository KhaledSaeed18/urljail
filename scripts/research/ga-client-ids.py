# Google Analytics 4 client IDs ("cid=<random>.<seconds>") from every run's guest request log:
# gtag.js draws the random part with Math.random() in the page, so a value seen in two runs, on
# different sites or at different times, is V8 random state shared between them (research R2).
# Usage: python3 -I ga-client-ids.py <runs-dir>
# Untrusted input: events are read as text, at most 64 MiB per run; nothing is executed.
import collections, json, os, re, sys

COLLECT = re.compile(r'(?:google-analytics\.com|analytics\.google\.com)/g/collect\?([^"\s]{0,4000})')

def main(runs):
    seen = collections.defaultdict(list)  # random part -> [(run, snapshot, tid, cid, url, started)]
    snaps = collections.Counter()
    for r in sorted(os.listdir(runs)):
        try:
            with open(os.path.join(runs, r, 'guest', 'events.jsonl'), 'rb') as f:
                b = f.read(64 << 20).decode('utf-8', 'replace')
            with open(os.path.join(runs, r, 'meta.json')) as f:
                m = json.load(f)
        except (OSError, ValueError):
            continue
        if 'g/collect' not in b:
            continue
        snap = (m.get('clone') or {}).get('snapshot', '-')
        snaps[snap] += 1
        cids = set()
        for q in COLLECT.findall(b):
            p = dict(kv.partition('=')[::2] for kv in q.replace('\\u0026', '&').split('&'))
            cid = p.get('cid', '')
            if re.fullmatch(r'\d{1,10}\.\d{1,10}', cid):
                cids.add((cid, p.get('tid', '?')))
        for cid, tid in cids:
            seen[cid.split('.')[0]].append((r, snap, tid, cid, m.get('url', '')[:60], m.get('started_at', '')[:19]))
    runs_with = sum(snaps.values())
    shared = {k: v for k, v in seen.items() if len({x[0] for x in v}) > 1}
    shared_runs = {x[0] for v in shared.values() for x in v}
    cross_site = {k: v for k, v in shared.items() if len({x[2] for x in v}) > 1 or len({re.sub(r'^https?://(www\.)?', '', x[4]).split('/')[0] for x in v}) > 1}
    cross_snap = {k: v for k, v in shared.items() if len({x[1] for x in v}) > 1}
    print(f'runs with a GA4 client id: {runs_with}; by snapshot: {dict(snaps)}')
    print(f'random parts: {len(seen)} distinct; {len(shared)} seen in more than one run ({len(shared_runs)} runs); '
          f'{len(cross_site)} of them across sites; {len(cross_snap)} across snapshots')
    for k, v in sorted(shared.items(), key=lambda kv: kv[1][0][5]):
        print(k)
        for x in v:
            print('   ', '\t'.join(x[1:]))

if __name__ == '__main__':
    main(sys.argv[1])
