package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

// The guest is hostile (docs/threat-model.md): it may only write these files, within these sizes.
var guestArtifacts = map[string]int64{
	"screenshot.png": 32 << 20,
	"dom.html":       32 << 20,
	"sslkeys.log":    4 << 20,
	"chrome.log":     4 << 20,
	"favicons.json":  16 << 10, // the favicons' URLs and types (agent: collectFavicons)
	"favicon-0":      256 << 10,
	"favicon-1":      256 << 10,
	"favicon-2":      256 << 10,
	"favicon-3":      256 << 10,
}

const (
	maxGuestTotal = 96 << 20 // all artifacts of one run
	maxEvents     = 200_000  // CDP events per run
	maxMethodLen  = 128
)

// dwell holds the observation bounds sent to the agent.
type dwell struct {
	min, max, jitter time.Duration
}

// runGuest asks the agent to detonate u and stores what comes back under runDir/guest/.
// Everything written there is guest-attested evidence.
func (s *Server) runGuest(ctx context.Context, r *run, c guestv1.GuestAgentServiceClient, url string, d dwell, runDir string) (*guestv1.Done, error) {
	dir := filepath.Join(runDir, "guest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	stream, err := c.Detonate(ctx, &guestv1.DetonateRequest{
		Url:      url,
		MinDwell: durationpb.New(d.min),
		MaxDwell: durationpb.New(d.max),
		Jitter:   durationpb.New(d.jitter),
		Profile:  r.browser,
	})
	if err != nil {
		return nil, fmt.Errorf("guest agent: %w", err)
	}

	ef, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	events := bufio.NewWriter(ef)
	defer events.Flush()
	enc := json.NewEncoder(events)

	arts := newArtifactSink(dir)
	defer arts.close()
	nEvents := 0

	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("guest agent ended the stream without a result")
		}
		if err != nil {
			return nil, fmt.Errorf("guest agent: %w", err)
		}
		switch msg := m.GetMsg().(type) {
		case *guestv1.DetonateResponse_Progress:
			if msg.Progress.GetStage() == guestv1.Stage_STAGE_NAVIGATING {
				r.mark("navigate")
			}
			if state, ok := stageState[msg.Progress.GetStage()]; ok {
				if err := r.send(state, msg.Progress.GetMessage()); err != nil {
					return nil, err
				}
			}
		case *guestv1.DetonateResponse_Event:
			if nEvents++; nEvents > maxEvents {
				continue // counted as a gap in the summary below
			}
			if err := enc.Encode(eventLine(msg.Event)); err != nil {
				return nil, err
			}
		case *guestv1.DetonateResponse_Artifact:
			if err := arts.write(msg.Artifact); err != nil {
				return nil, err
			}
		case *guestv1.DetonateResponse_Done:
			done := msg.Done
			if nEvents > maxEvents {
				done.DroppedEvents += int64(nEvents - maxEvents)
			}
			b, _ := protojson.MarshalOptions{UseProtoNames: true, Multiline: true}.Marshal(done)
			if err := os.WriteFile(filepath.Join(dir, "done.json"), append(b, '\n'), 0o600); err != nil {
				return nil, err
			}
			if done.GetError() != "" {
				return done, fmt.Errorf("guest: %s", done.GetError())
			}
			return done, nil
		}
	}
}

var stageState = map[guestv1.Stage]daemonv1.RunState{
	guestv1.Stage_STAGE_NAVIGATING: daemonv1.RunState_RUN_STATE_NAVIGATING,
	guestv1.Stage_STAGE_OBSERVING:  daemonv1.RunState_RUN_STATE_OBSERVING,
	guestv1.Stage_STAGE_COLLECTING: daemonv1.RunState_RUN_STATE_COLLECTING,
}

type eventJSON struct {
	Time    string          `json:"time"`
	Session string          `json:"session,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Invalid string          `json:"params_invalid,omitempty"` // params that weren't valid JSON, as text
}

func eventLine(e *guestv1.Event) eventJSON {
	method := e.GetMethod()
	if len(method) > maxMethodLen {
		method = method[:maxMethodLen]
	}
	line := eventJSON{Time: e.GetTime().AsTime().UTC().Format(time.RFC3339Nano), Session: e.GetSessionId(), Method: method}
	if p := e.GetParams(); len(p) > 0 {
		if json.Valid(p) {
			line.Params = p
		} else {
			line.Invalid = string(p)
		}
	}
	return line
}

// artifactSink writes chunked artifacts with name and size checks.
type artifactSink struct {
	dir   string
	open  map[string]*os.File
	sizes map[string]int64
	total int64
}

func newArtifactSink(dir string) *artifactSink {
	return &artifactSink{dir: dir, open: map[string]*os.File{}, sizes: map[string]int64{}}
}

func (a *artifactSink) write(art *guestv1.Artifact) error {
	name := art.GetName()
	limit, ok := guestArtifacts[name]
	if !ok {
		return fmt.Errorf("guest sent artifact %q, which isn't an allowed name", name)
	}
	a.sizes[name] += int64(len(art.GetData()))
	a.total += int64(len(art.GetData()))
	if a.sizes[name] > limit || a.total > maxGuestTotal {
		return fmt.Errorf("guest artifact %s exceeds its size limit", name)
	}
	f := a.open[name]
	if f == nil {
		var err error
		if f, err = os.OpenFile(filepath.Join(a.dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
			return err
		}
		a.open[name] = f
	}
	if _, err := f.Write(art.GetData()); err != nil {
		return err
	}
	if art.GetLast() {
		delete(a.open, name)
		return f.Close()
	}
	return nil
}

func (a *artifactSink) close() {
	for _, f := range a.open {
		f.Close()
	}
}
