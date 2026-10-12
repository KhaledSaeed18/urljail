// Command urljail is the operator CLI. It talks to urljaild over gRPC on a Unix socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/paths"
)

const usage = `usage: urljail [-socket path] <command> [args]

commands:
  detonate [-profile p] [-timeout d] <url>   open a URL in a fresh microVM
  version                                    show CLI and daemon versions
`

func main() {
	err := run()
	var exit exitError
	switch {
	case errors.As(err, &exit):
		os.Exit(int(exit))
	case err != nil:
		fmt.Fprintln(os.Stderr, "urljail:", err)
		os.Exit(1)
	}
}

// exitError ends the program with a status code and no extra message.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run() error {
	defSock, _ := paths.Socket()
	socket := flag.String("socket", defSock, "urljaild gRPC socket")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return exitError(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := grpc.NewClient("unix://"+*socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := daemonv1.NewDaemonServiceClient(conn)

	switch cmd, args := flag.Arg(0), flag.Args()[1:]; cmd {
	case "version":
		return cmdVersion(ctx, client)
	case "detonate":
		return cmdDetonate(ctx, client, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		flag.Usage()
		return exitError(2)
	}
}

func cmdVersion(ctx context.Context, c daemonv1.DaemonServiceClient) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := c.Version(ctx, &daemonv1.VersionRequest{})
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	fmt.Printf("urljaild %s\n  firecracker  %s\n  guest kernel %s\n  egress mode  %s\n",
		v.GetUrljail(), v.GetFirecracker(), v.GetGuestKernel(), v.GetEgressMode())
	return nil
}

func cmdDetonate(ctx context.Context, c daemonv1.DaemonServiceClient, args []string) error {
	fs := flag.NewFlagSet("detonate", flag.ContinueOnError)
	profile := fs.String("profile", "", "snapshot profile (default: daemon default)")
	timeout := fs.Duration("timeout", 0, "wall-clock limit for the run (default: daemon default)")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: urljail detonate [-profile p] [-timeout d] <url>")
		return exitError(2)
	}

	req := &daemonv1.DetonateRequest{Url: fs.Arg(0), Profile: *profile}
	if *timeout > 0 {
		req.Timeout = durationpb.New(*timeout)
	}
	// Cancelling ctx (Ctrl-C) cancels the stream; the daemon then tears the VM down.
	stream, err := c.Detonate(ctx, req)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}

	start := time.Now()
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return errors.New("stream ended without a final state")
		}
		if err != nil {
			return fmt.Errorf("daemon: %w", err)
		}
		elapsed := time.Since(start).Round(time.Millisecond)
		switch m.GetState() {
		case daemonv1.RunState_RUN_STATE_DONE:
			fmt.Printf("%8s  done  %s\n", elapsed, m.GetRunDir())
			return nil
		case daemonv1.RunState_RUN_STATE_FAILED:
			fmt.Printf("%8s  FAILED  %s\n", elapsed, m.GetError())
			return exitError(1)
		default:
			fmt.Printf("%8s  %-12s %s\n", elapsed, stateName(m.GetState()), m.GetMessage())
		}
	}
}

func stateName(s daemonv1.RunState) string {
	n := s.String()
	const prefix = "RUN_STATE_"
	if len(n) > len(prefix) {
		n = n[len(prefix):]
	}
	return n
}
