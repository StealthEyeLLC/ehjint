// Package hostidentity owns dedicated persistent Unix users and groups for
// EHJINT VMMs. It never invokes a shell and re-observes exact account truth.
package hostidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const (
	NamePrefix   = "ehjintm-"
	UIDRangeBase = 61000
	UIDRangeSize = 4000
	maxProbe     = UIDRangeSize
)

var namePattern = regexp.MustCompile(`^ehjintm-[a-z2-7]{16}$`)

// Identity is the complete immutable host account contract for one machine.
type Identity struct {
	MachineID         string `json:"machine_id"`
	Username          string `json:"username"`
	Groupname         string `json:"groupname"`
	UID               int    `json:"uid"`
	GID               int    `json:"gid"`
	KVMGID            int    `json:"kvm_gid"`
	Shell             string `json:"shell"`
	Home              string `json:"home"`
	SupplementaryGIDs []int  `json:"supplementary_gids"`
}

// Observation is exact passwd/group membership truth.
type Observation struct {
	Identity
	UserPresent    bool `json:"user_present"`
	GroupPresent   bool `json:"group_present"`
	PasswordLocked bool `json:"password_locked"`
}

// System permits deterministic tests and the real absolute-tool authority.
type System interface {
	LookupUser(context.Context, string) (passwdEntry, bool, error)
	LookupUID(context.Context, int) (passwdEntry, bool, error)
	LookupGroup(context.Context, string) (groupEntry, bool, error)
	LookupGID(context.Context, int) (groupEntry, bool, error)
	Groups(context.Context, string) ([]int, error)
	PasswordLocked(context.Context, string) (bool, error)
	Run(context.Context, string, ...string) error
}

// Authority creates, adopts, verifies, and removes exact per-machine identities.
type Authority struct {
	System System
}

type passwdEntry struct {
	Name        string
	UID, GID    int
	Home, Shell string
}
type groupEntry struct {
	Name    string
	GID     int
	Members []string
}

// Candidate deterministically derives a bounded collision-resistant name and
// one candidate UID/GID pair. The probe changes only the numeric candidate.
func Candidate(machineID string, kvmGID, probe int) (Identity, error) {
	identifier, err := contracts.ParseIdentifier(contracts.MachineIDKind, machineID)
	if err != nil {
		return Identity{}, err
	}
	if kvmGID <= 0 || probe < 0 || probe >= maxProbe {
		return Identity{}, fmt.Errorf("invalid KVM GID or identity probe")
	}
	encoded := strings.TrimPrefix(identifier.String(), "mach_")
	name := NamePrefix + encoded[:16]
	digest := sha256.Sum256([]byte(machineID))
	start := int(binary.BigEndian.Uint32(digest[:4]) % UIDRangeSize)
	numeric := UIDRangeBase + (start+probe)%UIDRangeSize
	return Identity{MachineID: machineID, Username: name, Groupname: name, UID: numeric, GID: numeric, KVMGID: kvmGID,
		Shell: "/usr/sbin/nologin", Home: "/nonexistent", SupplementaryGIDs: []int{kvmGID}}, nil
}

// Plan finds the first exact free numeric identity, while allowing an exact
// existing machine account to be adopted idempotently.
func (authority Authority) Plan(ctx context.Context, machineID string, kvmGID int) (Identity, error) {
	system := authority.system()
	for probe := 0; probe < maxProbe; probe++ {
		candidate, err := Candidate(machineID, kvmGID, probe)
		if err != nil {
			return Identity{}, err
		}
		user, userByName, err := system.LookupUser(ctx, candidate.Username)
		if err != nil {
			return Identity{}, err
		}
		group, groupByName, err := system.LookupGroup(ctx, candidate.Groupname)
		if err != nil {
			return Identity{}, err
		}
		if userByName || groupByName {
			if userByName && groupByName && user.UID == candidate.UID && user.GID == candidate.GID && group.GID == candidate.GID {
				return candidate, nil
			}
			return Identity{}, fmt.Errorf("host identity name collision for %s", candidate.Username)
		}
		if owner, found, err := system.LookupUID(ctx, candidate.UID); err != nil {
			return Identity{}, err
		} else if found && owner.Name != candidate.Username {
			continue
		}
		if owner, found, err := system.LookupGID(ctx, candidate.GID); err != nil {
			return Identity{}, err
		} else if found && owner.Name != candidate.Groupname {
			continue
		}
		return candidate, nil
	}
	return Identity{}, fmt.Errorf("no collision-free EHJINT system UID/GID remains")
}

// Ensure creates only the missing exact account components, rejects ambiguous
// partial ownership, locks the password, and re-observes every invariant.
func (authority Authority) Ensure(ctx context.Context, expected Identity) (Observation, error) {
	if err := expected.Validate(); err != nil {
		return Observation{}, err
	}
	system := authority.system()
	user, userExists, err := system.LookupUser(ctx, expected.Username)
	if err != nil {
		return Observation{}, err
	}
	group, groupExists, err := system.LookupGroup(ctx, expected.Groupname)
	if err != nil {
		return Observation{}, err
	}
	if groupExists && (group.GID != expected.GID || group.Name != expected.Groupname) {
		return Observation{}, fmt.Errorf("host group exists with conflicting identity")
	}
	if userExists && (user.UID != expected.UID || user.GID != expected.GID || user.Name != expected.Username) {
		return Observation{}, fmt.Errorf("host user exists with conflicting identity")
	}
	if byUID, found, err := system.LookupUID(ctx, expected.UID); err != nil {
		return Observation{}, err
	} else if found && byUID.Name != expected.Username {
		return Observation{}, fmt.Errorf("host UID belongs to another user")
	}
	if byGID, found, err := system.LookupGID(ctx, expected.GID); err != nil {
		return Observation{}, err
	} else if found && byGID.Name != expected.Groupname {
		return Observation{}, fmt.Errorf("host GID belongs to another group")
	}
	if !groupExists {
		if err := system.Run(ctx, "/usr/sbin/groupadd", "--system", "--gid", strconv.Itoa(expected.GID), expected.Groupname); err != nil {
			return Observation{}, fmt.Errorf("create EHJINT machine group: %w", err)
		}
	}
	if !userExists {
		if err := system.Run(ctx, "/usr/sbin/useradd", "--system", "--uid", strconv.Itoa(expected.UID), "--gid", strconv.Itoa(expected.GID),
			"--groups", strconv.Itoa(expected.KVMGID), "--home-dir", expected.Home, "--no-create-home", "--shell", expected.Shell,
			"--comment", "EHJINT machine "+expected.MachineID, expected.Username); err != nil {
			return Observation{}, fmt.Errorf("create EHJINT machine user: %w", err)
		}
	}
	if err := system.Run(ctx, "/usr/sbin/usermod", "--lock", "--groups", strconv.Itoa(expected.KVMGID), "--append", expected.Username); err != nil {
		return Observation{}, fmt.Errorf("lock and constrain EHJINT machine user: %w", err)
	}
	return authority.Observe(ctx, expected)
}

// Observe refuses any difference in account, shell, home, primary group,
// supplementary groups, or password lock.
func (authority Authority) Observe(ctx context.Context, expected Identity) (Observation, error) {
	if err := expected.Validate(); err != nil {
		return Observation{}, err
	}
	system := authority.system()
	user, userExists, err := system.LookupUser(ctx, expected.Username)
	if err != nil {
		return Observation{}, err
	}
	group, groupExists, err := system.LookupGroup(ctx, expected.Groupname)
	if err != nil {
		return Observation{}, err
	}
	observation := Observation{Identity: expected, UserPresent: userExists, GroupPresent: groupExists}
	if !userExists || !groupExists {
		return observation, fmt.Errorf("EHJINT machine identity is incomplete")
	}
	if user.Name != expected.Username || user.UID != expected.UID || user.GID != expected.GID || user.Home != expected.Home || user.Shell != expected.Shell {
		return observation, fmt.Errorf("EHJINT machine user properties conflict")
	}
	if group.Name != expected.Groupname || group.GID != expected.GID || len(group.Members) != 0 {
		return observation, fmt.Errorf("EHJINT machine primary group properties conflict")
	}
	groups, err := system.Groups(ctx, expected.Username)
	if err != nil {
		return observation, err
	}
	sort.Ints(groups)
	wanted := append([]int(nil), expected.SupplementaryGIDs...)
	sort.Ints(wanted)
	if !equalInts(groups, wanted) {
		return observation, fmt.Errorf("EHJINT machine supplementary groups conflict: got %v want %v", groups, wanted)
	}
	locked, err := system.PasswordLocked(ctx, expected.Username)
	if err != nil {
		return observation, err
	}
	observation.PasswordLocked = locked
	if !locked {
		return observation, fmt.Errorf("EHJINT machine password is not locked")
	}
	return observation, nil
}

// Remove deletes only an exactly re-observed machine account and verifies
// positive absence. Callers must already prove the VMM and runtime are absent.
func (authority Authority) Remove(ctx context.Context, expected Identity) error {
	if _, err := authority.Observe(ctx, expected); err != nil {
		return fmt.Errorf("refuse ambiguous host identity removal: %w", err)
	}
	system := authority.system()
	if err := system.Run(ctx, "/usr/sbin/userdel", expected.Username); err != nil {
		return fmt.Errorf("remove EHJINT machine user: %w", err)
	}
	if err := system.Run(ctx, "/usr/sbin/groupdel", expected.Groupname); err != nil {
		return fmt.Errorf("remove EHJINT machine group: %w", err)
	}
	if _, found, err := system.LookupUser(ctx, expected.Username); err != nil {
		return err
	} else if found {
		return fmt.Errorf("EHJINT machine user remains after removal")
	}
	if _, found, err := system.LookupUID(ctx, expected.UID); err != nil {
		return err
	} else if found {
		return fmt.Errorf("EHJINT machine UID remains allocated")
	}
	if _, found, err := system.LookupGroup(ctx, expected.Groupname); err != nil {
		return err
	} else if found {
		return fmt.Errorf("EHJINT machine group remains after removal")
	}
	if _, found, err := system.LookupGID(ctx, expected.GID); err != nil {
		return err
	} else if found {
		return fmt.Errorf("EHJINT machine GID remains allocated")
	}
	return nil
}

func (identity Identity) Validate() error {
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, identity.MachineID); err != nil {
		return err
	}
	if !namePattern.MatchString(identity.Username) || identity.Groupname != identity.Username {
		return fmt.Errorf("invalid EHJINT machine account name")
	}
	if identity.UID < UIDRangeBase || identity.UID >= UIDRangeBase+UIDRangeSize || identity.GID != identity.UID || identity.KVMGID <= 0 {
		return fmt.Errorf("invalid EHJINT machine numeric identity")
	}
	if identity.Shell != "/usr/sbin/nologin" || identity.Home != "/nonexistent" || len(identity.SupplementaryGIDs) != 1 || identity.SupplementaryGIDs[0] != identity.KVMGID {
		return fmt.Errorf("unsafe EHJINT machine login or group contract")
	}
	return nil
}

func (authority Authority) system() System {
	if authority.System != nil {
		return authority.System
	}
	return realSystem{}
}
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type realSystem struct{}

func (realSystem) LookupUser(ctx context.Context, value string) (passwdEntry, bool, error) {
	return lookupPasswd(ctx, value)
}
func (realSystem) LookupUID(ctx context.Context, value int) (passwdEntry, bool, error) {
	return lookupPasswd(ctx, strconv.Itoa(value))
}
func (realSystem) LookupGroup(ctx context.Context, value string) (groupEntry, bool, error) {
	return lookupGroup(ctx, value)
}
func (realSystem) LookupGID(ctx context.Context, value int) (groupEntry, bool, error) {
	return lookupGroup(ctx, strconv.Itoa(value))
}
func (realSystem) Groups(ctx context.Context, username string) ([]int, error) {
	data, found, err := output(ctx, "/usr/bin/id", "-G", username)
	if err != nil || !found {
		return nil, fmt.Errorf("observe EHJINT machine groups: %w", err)
	}
	primary, ok, err := lookupPasswd(ctx, username)
	if err != nil || !ok {
		return nil, fmt.Errorf("observe EHJINT primary group: %w", err)
	}
	var result []int
	for _, raw := range strings.Fields(string(data)) {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("parse EHJINT group list")
		}
		if value != primary.GID {
			result = append(result, value)
		}
	}
	return result, nil
}
func (realSystem) PasswordLocked(ctx context.Context, username string) (bool, error) {
	data, found, err := output(ctx, "/usr/bin/getent", "shadow", username)
	if err != nil || !found {
		return false, fmt.Errorf("observe EHJINT shadow entry: %w", err)
	}
	fields := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(fields) < 2 {
		return false, fmt.Errorf("malformed EHJINT shadow entry")
	}
	return strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*"), nil
}
func (realSystem) Run(ctx context.Context, path string, args ...string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("host identity tool path is not absolute")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var stderr bytes.Buffer
	command.Stdout = &stderr
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		text := strings.TrimSpace(stderr.String())
		if len(text) > 1024 {
			text = text[:1024]
		}
		return fmt.Errorf("%s failed: %w: %s", filepath.Base(path), err, text)
	}
	return nil
}
func lookupPasswd(ctx context.Context, key string) (passwdEntry, bool, error) {
	data, found, err := output(ctx, "/usr/bin/getent", "passwd", key)
	if err != nil || !found {
		return passwdEntry{}, found, err
	}
	fields := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(fields) != 7 {
		return passwdEntry{}, false, fmt.Errorf("malformed passwd entry")
	}
	uid, e1 := strconv.Atoi(fields[2])
	gid, e2 := strconv.Atoi(fields[3])
	if e1 != nil || e2 != nil {
		return passwdEntry{}, false, fmt.Errorf("malformed passwd numeric identity")
	}
	return passwdEntry{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}, true, nil
}
func lookupGroup(ctx context.Context, key string) (groupEntry, bool, error) {
	data, found, err := output(ctx, "/usr/bin/getent", "group", key)
	if err != nil || !found {
		return groupEntry{}, found, err
	}
	fields := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(fields) != 4 {
		return groupEntry{}, false, fmt.Errorf("malformed group entry")
	}
	gid, err := strconv.Atoi(fields[2])
	if err != nil {
		return groupEntry{}, false, fmt.Errorf("malformed group GID")
	}
	var members []string
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return groupEntry{Name: fields[0], GID: gid, Members: members}, true, nil
}
func output(ctx context.Context, path string, args ...string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	data, err := command.Output()
	if err == nil {
		return data, true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 2 {
		return nil, false, nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, false, ctx.Err()
	}
	return nil, false, fmt.Errorf("run %s: %w", filepath.Base(path), err)
}

// AssertTools verifies the immutable absolute host-tool paths before mutation.
func AssertTools() error {
	for _, path := range []string{"/usr/bin/getent", "/usr/bin/id", "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/sbin/userdel", "/usr/sbin/groupdel", "/usr/sbin/nologin"} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("required host identity tool %s: %w", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unsafe host identity tool %s", path)
		}
	}
	return nil
}
