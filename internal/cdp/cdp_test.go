package cdp

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto"
	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/go-json-experiment/json"
)

// fakeBrowser answers Page.navigate and emits one event first, the way Chrome interleaves them.
func fakeBrowser(t *testing.T, fromClient io.Reader, toClient io.Writer) {
	r := bufio.NewReader(fromClient)
	for {
		b, err := r.ReadBytes(0)
		if err != nil {
			return
		}
		var msg cdproto.Message
		if err := json.Unmarshal(b[:len(b)-1], &msg); err != nil {
			t.Errorf("client sent bad JSON: %v", err)
			return
		}
		io.WriteString(toClient, `{"method":"Page.loadEventFired","sessionId":"S1","params":{"timestamp":1.5}}`+"\x00")
		switch msg.Method {
		case "Page.navigate":
			if msg.SessionID != "S1" || !strings.Contains(string(msg.Params), `"url":"https://example.com/"`) {
				t.Errorf("navigate: session %q params %s", msg.SessionID, msg.Params)
			}
			io.WriteString(toClient, `{"id":`+itoa(msg.ID)+`,"sessionId":"S1","result":{"frameId":"F1","loaderId":"L1"}}`+"\x00")
		default:
			io.WriteString(toClient, `{"id":`+itoa(msg.ID)+`,"error":{"code":-32601,"message":"'`+string(msg.Method)+`' wasn't found"}}`+"\x00")
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestNavigateOverPipe(t *testing.T) {
	cr, cw := io.Pipe() // client → browser
	br, bw := io.Pipe() // browser → client
	go fakeBrowser(t, cr, bw)
	c := New(cw, br)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pctx := cdpctx.WithExecutor(ctx, c.Session("S1"))

	frame, _, _, _, err := page.Navigate("https://example.com/").Do(pctx)
	if err != nil {
		t.Fatal(err)
	}
	if frame != "F1" {
		t.Fatalf("frame = %q", frame)
	}
	select {
	case ev := <-c.Events():
		if ev.Method != "Page.loadEventFired" || ev.SessionID != "S1" {
			t.Fatalf("event %s on %q", ev.Method, ev.SessionID)
		}
	case <-ctx.Done():
		t.Fatal("no event")
	}

	err = c.Browser().Execute(ctx, "Nope.method", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "wasn't found") {
		t.Fatalf("protocol error not surfaced: %v", err)
	}
}

func TestConnClosed(t *testing.T) {
	cr, cw := io.Pipe()
	cr.Close() // like a pipe whose reader (Chrome) has exited: writes fail instead of blocking
	br, bw := io.Pipe()
	c := New(cw, br)
	bw.Close()
	<-c.Done()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Browser().Execute(ctx, "Browser.getVersion", nil, nil); err == nil {
		t.Fatal("call on a closed connection succeeded")
	}
}
