// Package operator identifies the person urljaild works for. The daemon runs as root
// (ADR 0014); everything it hands back — the API socket, run directories, the Firecracker
// process — belongs to the operator instead.
package operator

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Operator is an unprivileged local user.
type Operator struct {
	UID, GID int
	Name     string
	Home     string
}

// FromSudo returns the user who started the daemon with sudo (SUDO_UID, SUDO_GID).
func FromSudo() (Operator, error) {
	uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uid == "" || gid == "" {
		return Operator{}, errors.New("SUDO_UID/SUDO_GID not set: start urljaild with sudo, or pass -operator")
	}
	return Lookup(uid)
}

// Lookup finds an operator by name or numeric UID.
func Lookup(nameOrUID string) (Operator, error) {
	var u *user.User
	var err error
	if _, convErr := strconv.Atoi(nameOrUID); convErr == nil {
		u, err = user.LookupId(nameOrUID)
	} else {
		u, err = user.Lookup(nameOrUID)
	}
	if err != nil {
		return Operator{}, err
	}
	o := Operator{Name: u.Username, Home: u.HomeDir}
	if o.UID, err = strconv.Atoi(u.Uid); err != nil {
		return o, err
	}
	if o.GID, err = strconv.Atoi(u.Gid); err != nil {
		return o, err
	}
	if o.UID == 0 {
		return o, errors.New("the operator must not be root")
	}
	return o, nil
}

// Chown gives path to the operator.
func (o Operator) Chown(path string) error { return os.Lchown(path, o.UID, o.GID) }

// ChownTree gives path and everything under it to the operator.
func (o Operator) ChownTree(root string) error {
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return o.Chown(p)
	})
}

// MkdirAll creates dir (and missing parents below an existing ancestor) owned by the operator.
func (o Operator) MkdirAll(dir string, perm os.FileMode) error {
	var created []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		created = append(created, d)
		if d == filepath.Dir(d) {
			break
		}
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	for _, d := range created {
		if err := o.Chown(d); err != nil {
			return fmt.Errorf("chown %s: %w", d, err)
		}
	}
	return nil
}
