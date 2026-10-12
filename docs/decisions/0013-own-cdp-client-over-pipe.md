# 0013: Own CDP client over --remote-debugging-pipe

- Status: Accepted
- Date: 2026-10-12

## Context
The guest agent drives Chrome over the DevTools Protocol. The design requires `--remote-debugging-pipe` (no TCP debugging port a DNS-rebinding page could reach; [network.md](../network.md#dns), [guest-image.md](../guest-image.md#chromium-configuration)). On 2026-10-12, chromedp's pipe support existed only in releases from the previous nine days (v0.17.0, 2026-10-03, followed by six more releases up to v0.21.0 on 2026-10-11); v0.16.0 (July) can't take a custom transport. Separately, which CDP domains are enabled is visible to pages: `Runtime.enable` is a known automation tell, and "CDP-detectable artifacts" is a P6 research factor ([anti-cloaking.md](../research/anti-cloaking.md)). chromedp enables several domains per target by itself.

## Decision
`internal/cdp` is a small client of our own: NUL-delimited JSON on Chrome's fds 3/4, request/response matching by ID, flat-mode sessions, and a bounded event queue that counts drops instead of blocking (blocking would stall command responses on the same pipe). Its `Session` implements cdproto's `cdp.Executor`, so the typed commands from **github.com/chromedp/cdproto** (pinned to commit `a19bff23514f`, 2026-09-22, Chrome 156 protocol definitions) run over it unchanged.

The client enables nothing by itself. The agent enables `Network` and `Page` (plus lifecycle events) only; **no `Runtime.enable`**. The DOM is read with `DOM.getOuterHTML`, so no script runs in the page.

## Alternatives considered
- **chromedp v0.21.0 / v0.17.1:** least code, but days-old releases in a burst of churn, inside the component facing hostile content; and its per-target domain setup isn't under our control.
- **chromedp now, own client in P6:** works, but does the CDP integration twice.
- **Websocket debugging on 127.0.0.1:** rejected by design (DNS rebinding to loopback).

## Consequences
- Which domains are enabled is an explicit, switchable decision, ready to be a P6 condition.
- ~200 lines to own and test (`internal/cdp` has unit tests against a fake browser).
- cdproto updates are deliberate: bump the pinned commit when Chrome's protocol changes something we use.
