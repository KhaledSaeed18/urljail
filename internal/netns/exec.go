package netns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// run executes a command as the daemon (root) and returns its stdout.
func run(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func ip(ctx context.Context, args ...string) error {
	_, err := run(ctx, nil, "ip", args...)
	return err
}

// in runs a command inside network namespace ns.
func in(ctx context.Context, ns string, name string, args ...string) (string, error) {
	return run(ctx, nil, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

// sysctls sets kernel parameters inside ns.
func sysctls(ctx context.Context, ns string, kv ...string) error {
	_, err := in(ctx, ns, "sysctl", append([]string{"-q", "-w"}, kv...)...)
	return err
}

// killAll SIGKILLs every process still inside ns. Processes that dropped privileges (unbound,
// tcpdump) lose their parent-death signal, so they can outlive a killed daemon and keep a
// deleted namespace alive; nothing of ours may survive its namespace.
func killAll(ctx context.Context, ns string) []int {
	out, err := run(ctx, nil, "ip", "netns", "pids", ns)
	if err != nil {
		return nil
	}
	var killed []int
	for _, f := range strings.Fields(out) {
		if pid, err := strconv.Atoi(f); err == nil && pid > 1 && syscall.Kill(pid, syscall.SIGKILL) == nil {
			killed = append(killed, pid)
		}
	}
	return killed
}

// delete kills what's left in ns, then deletes it.
func deleteNS(ctx context.Context, ns string) error {
	killAll(ctx, ns)
	return ip(ctx, "netns", "del", ns)
}

// namespaces lists named network namespaces.
func namespaces(ctx context.Context) ([]string, error) {
	out, err := run(ctx, nil, "ip", "netns", "list")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	return names, nil
}
