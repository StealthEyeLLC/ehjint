package controller

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Policy is explicit controller authorization policy. Root is always
// authorized. Members of GroupID may use ordinary operations; RootOnly names
// require UID 0 even when the socket is group-accessible.
type Policy struct {
	GroupID  int
	RootOnly map[string]bool
}

// Authorize verifies an already observed peer against explicit operation
// policy. It does not rely on filesystem mode as authorization.
func (policy Policy) Authorize(peer Peer, operation string) error {
	if peer.UID == 0 {
		return nil
	}
	if policy.RootOnly[operation] {
		return fmt.Errorf("operation %q requires UID 0", operation)
	}
	if policy.GroupID < 0 {
		return fmt.Errorf("controller group policy is not configured")
	}
	for _, group := range peer.Groups {
		if group == policy.GroupID {
			return nil
		}
	}
	return fmt.Errorf("peer UID %d is not a verified member of controller group %d", peer.UID, policy.GroupID)
}

func inspectPeer(connection *net.UnixConn) (Peer, error) {
	if connection == nil {
		return Peer{}, fmt.Errorf("Unix connection is required")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("access Unix peer socket: %w", err)
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("inspect Unix peer credentials: %w", err)
	}
	if socketErr != nil {
		return Peer{}, fmt.Errorf("read SO_PEERCRED: %w", socketErr)
	}
	if credentials == nil || credentials.Pid <= 0 {
		return Peer{}, fmt.Errorf("SO_PEERCRED returned invalid process identity")
	}
	pid := int(credentials.Pid)
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return Peer{}, fmt.Errorf("anchor peer process identity: %w", err)
	}
	defer unix.Close(pidfd)
	if err := pidfdAlive(pidfd); err != nil {
		return Peer{}, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return Peer{}, fmt.Errorf("read peer process status: %w", err)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Peer{}, fmt.Errorf("read peer process start identity: %w", err)
	}
	peer, err := parsePeerStatus(pid, int(credentials.Uid), int(credentials.Gid), status, stat)
	if err != nil {
		return Peer{}, err
	}
	if err := pidfdAlive(pidfd); err != nil {
		return Peer{}, err
	}
	return peer, nil
}

func pidfdAlive(pidfd int) error {
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("peer process exited during authorization")
		}
		return fmt.Errorf("verify anchored peer process: %w", err)
	}
	return nil
}

func parsePeerStatus(pid, socketUID, socketGID int, status, stat []byte) (Peer, error) {
	values := make(map[string][]string)
	for _, line := range strings.Split(string(status), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		values[name] = strings.Fields(value)
	}
	uids := values["Uid"]
	gids := values["Gid"]
	if len(uids) != 4 || len(gids) != 4 {
		return Peer{}, fmt.Errorf("peer status lacks complete UID/GID identity")
	}
	uid, err := strconv.Atoi(uids[0])
	if err != nil || uid != socketUID {
		return Peer{}, fmt.Errorf("SO_PEERCRED UID differs from peer status")
	}
	gid, err := strconv.Atoi(gids[0])
	if err != nil || gid != socketGID {
		return Peer{}, fmt.Errorf("SO_PEERCRED GID differs from peer status")
	}
	groups := make([]int, 0, len(values["Groups"])+1)
	seen := map[int]bool{}
	for _, raw := range append([]string{strconv.Itoa(gid)}, values["Groups"]...) {
		group, parseErr := strconv.Atoi(raw)
		if parseErr != nil || group < 0 {
			return Peer{}, fmt.Errorf("peer status contains invalid group identity")
		}
		if !seen[group] {
			seen[group] = true
			groups = append(groups, group)
		}
	}
	sort.Ints(groups)
	text := strings.TrimSpace(string(stat))
	closeParen := strings.LastIndex(text, ")")
	if closeParen < 0 || closeParen+2 > len(text) {
		return Peer{}, fmt.Errorf("peer stat has invalid command boundary")
	}
	fields := strings.Fields(text[closeParen+2:])
	if len(fields) <= 19 {
		return Peer{}, fmt.Errorf("peer stat lacks start identity")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return Peer{}, fmt.Errorf("peer stat start identity is invalid")
	}
	return Peer{PID: pid, UID: uid, GID: gid, Groups: groups, StartIdentity: fields[19]}, nil
}
