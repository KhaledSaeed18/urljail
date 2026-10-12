// Package cdp is a minimal Chrome DevTools Protocol client over --remote-debugging-pipe
// (ADR 0013). Chrome reads commands on fd 3 and writes responses and events on fd 4, each
// message JSON terminated by a NUL byte. There is no TCP debugging port for a page to reach.
//
// Sessions implement cdp.Executor from github.com/chromedp/cdproto, so cdproto's typed commands
// run over the pipe: page.Navigate(u).Do(cdp.WithExecutor(ctx, session)). Only the domains the
// caller enables are enabled; this client turns nothing on by itself.
package cdp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/chromedp/cdproto"
	"github.com/chromedp/cdproto/target"
	"github.com/go-json-experiment/json"
)

// eventQueue is how many events can wait for the consumer before new ones are dropped
// (and counted). Blocking instead would stall command responses on the same pipe.
const eventQueue = 16384

// maxMessage bounds a single message from Chrome (screenshots arrive base64-encoded).
const maxMessage = 64 << 20

// Conn is one pipe connection to a browser.
type Conn struct {
	w   io.Writer
	wmu sync.Mutex

	next atomic.Int64

	mu    sync.Mutex
	calls map[int64]chan *cdproto.Message

	events  chan *cdproto.Message
	dropped atomic.Int64

	done chan struct{}
	err  error // set before done is closed
}

// New starts reading from r (Chrome's fd 4) and writes commands to w (Chrome's fd 3).
func New(w io.Writer, r io.Reader) *Conn {
	c := &Conn{
		w:      w,
		calls:  make(map[int64]chan *cdproto.Message),
		events: make(chan *cdproto.Message, eventQueue),
		done:   make(chan struct{}),
	}
	go c.read(bufio.NewReaderSize(r, 1<<20))
	return c
}

func (c *Conn) read(r *bufio.Reader) {
	var err error
	defer func() {
		c.err = err
		close(c.done)
		close(c.events)
	}()
	for {
		var b []byte
		if b, err = readMessage(r); err != nil {
			return
		}
		msg := new(cdproto.Message)
		if err = json.Unmarshal(b, msg); err != nil {
			err = fmt.Errorf("cdp: bad message from browser: %w", err)
			return
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.calls[msg.ID]
			delete(c.calls, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		select {
		case c.events <- msg:
		default:
			c.dropped.Add(1)
		}
	}
}

func readMessage(r *bufio.Reader) ([]byte, error) {
	var msg []byte
	for {
		chunk, err := r.ReadSlice(0)
		msg = append(msg, chunk...)
		if len(msg) > maxMessage {
			return nil, fmt.Errorf("cdp: message over %d bytes", maxMessage)
		}
		switch {
		case err == nil:
			return msg[:len(msg)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

// Events delivers every CDP event in arrival order. It is closed when the connection ends.
func (c *Conn) Events() <-chan *cdproto.Message { return c.events }

// Dropped is how many events were discarded because the consumer fell behind.
func (c *Conn) Dropped() int64 { return c.dropped.Load() }

// Done is closed when the browser side of the pipe closes.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Browser is the browser-level session (no session ID).
func (c *Conn) Browser() Session { return Session{conn: c} }

// Session returns the flat-mode session for an attached target.
func (c *Conn) Session(id target.SessionID) Session { return Session{conn: c, ID: id} }

// Session addresses commands to one target. It implements cdproto's cdp.Executor.
type Session struct {
	conn *Conn
	ID   target.SessionID
}

// Execute sends method with params and decodes the result into res (which may be nil).
func (s Session) Execute(ctx context.Context, method string, params, res any) error {
	return s.conn.call(ctx, s.ID, method, params, res)
}

func (c *Conn) call(ctx context.Context, session target.SessionID, method string, params, res any) error {
	msg := cdproto.Message{ID: c.next.Add(1), SessionID: session, Method: cdproto.MethodType(method)}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("cdp %s: %w", method, err)
		}
		msg.Params = b
	}
	b, err := json.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("cdp %s: %w", method, err)
	}

	ch := make(chan *cdproto.Message, 1)
	c.mu.Lock()
	c.calls[msg.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.calls, msg.ID)
		c.mu.Unlock()
	}()

	c.wmu.Lock()
	_, err = c.w.Write(append(b, 0))
	c.wmu.Unlock()
	if err != nil {
		return fmt.Errorf("cdp %s: write: %w", method, err)
	}

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return fmt.Errorf("cdp %s: %w", method, resp.Error)
		}
		if res != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, res); err != nil {
				return fmt.Errorf("cdp %s: decoding result: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("cdp %s: connection closed: %v", method, c.err)
	}
}
