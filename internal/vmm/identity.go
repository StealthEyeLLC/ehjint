package vmm

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ProcessIdentity is the complete host-observed VMM identity required to
// defend against PID reuse and privilege drift. PIDFD is an observation handle
// and is deliberately omitted from durable JSON.
type ProcessIdentity struct {
	PID               int      `json:"pid"`
	StartTime         uint64   `json:"start_time"`
	State             string   `json:"state"`
	ExecutablePath    string   `json:"executable_path"`
	ExecutableSHA256  string   `json:"executable_sha256"`
	RealUID           uint32   `json:"real_uid"`
	EffectiveUID      uint32   `json:"effective_uid"`
	SavedUID          uint32   `json:"saved_uid"`
	FilesystemUID     uint32   `json:"filesystem_uid"`
	RealGID           uint32   `json:"real_gid"`
	EffectiveGID      uint32   `json:"effective_gid"`
	SavedGID          uint32   `json:"saved_gid"`
	FilesystemGID     uint32   `json:"filesystem_gid"`
	UID               uint32   `json:"uid"`
	GID               uint32   `json:"gid"`
	SupplementaryGIDs []uint32 `json:"supplementary_gids"`
	NoNewPrivs        bool     `json:"no_new_privs"`
	SeccompMode       int      `json:"seccomp_mode"`
	SeccompFilters    int      `json:"seccomp_filters"`
	CapInheritable    uint64   `json:"cap_inheritable"`
	CapPermitted      uint64   `json:"cap_permitted"`
	CapEffective      uint64   `json:"cap_effective"`
	CapBounding       uint64   `json:"cap_bounding"`
	CapAmbient        uint64   `json:"cap_ambient"`
	PIDFD             int      `json:"-"`
}

// InspectProcess reads one stable /proc snapshot and opens a pidfd. The caller
// must close PIDFD when the identity is no longer needed.
func InspectProcess(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, fmt.Errorf("invalid VMM PID")
	}
	procRoot := fmt.Sprintf("/proc/%d", pid)
	firstStat, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read VMM stat: %w", err)
	}
	state, startTime, err := parseProcessStat(string(firstStat))
	if err != nil {
		return ProcessIdentity{}, err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("open VMM pidfd: %w", err)
	}
	closePIDFD := true
	defer func() {
		if closePIDFD {
			_ = unix.Close(pidfd)
		}
	}()

	statusFile, err := os.Open(filepath.Join(procRoot, "status"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("open VMM status: %w", err)
	}
	fields, parseErr := parseStatus(statusFile)
	closeErr := statusFile.Close()
	if parseErr != nil {
		return ProcessIdentity{}, parseErr
	}
	if closeErr != nil {
		return ProcessIdentity{}, fmt.Errorf("close VMM status: %w", closeErr)
	}
	executable, err := os.Readlink(filepath.Join(procRoot, "exe"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read VMM executable link: %w", err)
	}
	if strings.HasSuffix(executable, " (deleted)") {
		return ProcessIdentity{}, fmt.Errorf("VMM executable has been unlinked")
	}
	executable = filepath.Clean(executable)
	digest, err := hashPath(filepath.Join(procRoot, "exe"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	secondStat, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("re-read VMM stat: %w", err)
	}
	secondState, secondStart, err := parseProcessStat(string(secondStat))
	if err != nil {
		return ProcessIdentity{}, err
	}
	if secondStart != startTime || deadProcessState(secondState) {
		return ProcessIdentity{}, fmt.Errorf("VMM process identity changed during observation")
	}
	state = secondState

	identity := ProcessIdentity{
		PID: pid, StartTime: startTime, State: state,
		ExecutablePath: executable, ExecutableSHA256: digest,
		RealUID: fields.uids[0], EffectiveUID: fields.uids[1], SavedUID: fields.uids[2], FilesystemUID: fields.uids[3],
		RealGID: fields.gids[0], EffectiveGID: fields.gids[1], SavedGID: fields.gids[2], FilesystemGID: fields.gids[3],
		UID: fields.uids[1], GID: fields.gids[1], SupplementaryGIDs: fields.groups,
		NoNewPrivs: fields.noNewPrivs, SeccompMode: fields.seccomp, SeccompFilters: fields.seccompFilters,
		CapInheritable: fields.capInh, CapPermitted: fields.capPrm, CapEffective: fields.capEff,
		CapBounding: fields.capBnd, CapAmbient: fields.capAmb, PIDFD: pidfd,
	}
	closePIDFD = false
	return identity, nil
}

func (identity ProcessIdentity) Validate(expectedPath, expectedDigest string, uid, gid uint32, groups []uint32) error {
	if identity.PID <= 0 || identity.StartTime == 0 || identity.PIDFD < 0 || deadProcessState(identity.State) {
		return fmt.Errorf("VMM process identity is incomplete or not live")
	}
	if filepath.Clean(identity.ExecutablePath) != filepath.Clean(expectedPath) {
		return fmt.Errorf("VMM executable path identity mismatch")
	}
	if identity.ExecutableSHA256 != expectedDigest {
		return fmt.Errorf("VMM executable digest identity mismatch")
	}
	if identity.RealUID != uid || identity.EffectiveUID != uid || identity.SavedUID != uid || identity.FilesystemUID != uid || identity.UID != uid {
		return fmt.Errorf("VMM UID identity mismatch")
	}
	if identity.RealGID != gid || identity.EffectiveGID != gid || identity.SavedGID != gid || identity.FilesystemGID != gid || identity.GID != gid {
		return fmt.Errorf("VMM GID identity mismatch")
	}
	if !equalGroups(identity.SupplementaryGIDs, groups) {
		return fmt.Errorf("VMM supplementary group identity mismatch")
	}
	if !identity.NoNewPrivs {
		return fmt.Errorf("VMM no_new_privs is not active")
	}
	if identity.CapInheritable != 0 || identity.CapPermitted != 0 || identity.CapEffective != 0 || identity.CapBounding != 0 || identity.CapAmbient != 0 {
		return fmt.Errorf("VMM retained Linux capabilities")
	}
	return nil
}

// MatchesDurable verifies that a new host observation is the same exact
// process described by durable state. It intentionally does not require the
// scheduler state byte to remain equal because a live process may move between
// running and sleeping while retaining the same identity.
func (identity ProcessIdentity) MatchesDurable(expected ProcessIdentity) error {
	if identity.PID != expected.PID {
		return fmt.Errorf("VMM PID identity mismatch")
	}
	if identity.StartTime != expected.StartTime {
		return fmt.Errorf("VMM process start identity mismatch")
	}
	if identity.ExecutablePath != expected.ExecutablePath {
		return fmt.Errorf("VMM executable path identity mismatch")
	}
	if identity.ExecutableSHA256 != expected.ExecutableSHA256 {
		return fmt.Errorf("VMM executable digest identity mismatch")
	}
	if identity.RealUID != expected.RealUID || identity.EffectiveUID != expected.EffectiveUID || identity.SavedUID != expected.SavedUID || identity.FilesystemUID != expected.FilesystemUID || identity.UID != expected.UID {
		return fmt.Errorf("VMM durable UID identity mismatch")
	}
	if identity.RealGID != expected.RealGID || identity.EffectiveGID != expected.EffectiveGID || identity.SavedGID != expected.SavedGID || identity.FilesystemGID != expected.FilesystemGID || identity.GID != expected.GID {
		return fmt.Errorf("VMM durable GID identity mismatch")
	}
	if !equalGroups(identity.SupplementaryGIDs, expected.SupplementaryGIDs) {
		return fmt.Errorf("VMM durable supplementary group mismatch")
	}
	if identity.NoNewPrivs != expected.NoNewPrivs || identity.SeccompMode != expected.SeccompMode || identity.SeccompFilters != expected.SeccompFilters {
		return fmt.Errorf("VMM durable process isolation mismatch")
	}
	if identity.CapInheritable != expected.CapInheritable || identity.CapPermitted != expected.CapPermitted || identity.CapEffective != expected.CapEffective || identity.CapBounding != expected.CapBounding || identity.CapAmbient != expected.CapAmbient {
		return fmt.Errorf("VMM durable capability identity mismatch")
	}
	if deadProcessState(identity.State) {
		return fmt.Errorf("VMM durable process is not live")
	}
	return nil
}

type statusFields struct {
	uids                                   [4]uint32
	gids                                   [4]uint32
	groups                                 []uint32
	noNewPrivs                             bool
	seccomp, seccompFilters                int
	capInh, capPrm, capEff, capBnd, capAmb uint64
}

func parseStartTime(stat string) (uint64, error) {
	_, start, err := parseProcessStat(stat)
	return start, err
}

func parseProcessStat(stat string) (string, uint64, error) {
	closeIndex := strings.LastIndex(stat, ")")
	if closeIndex < 0 || closeIndex+2 >= len(stat) {
		return "", 0, fmt.Errorf("VMM stat has invalid comm field")
	}
	fields := strings.Fields(stat[closeIndex+2:])
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return "", 0, fmt.Errorf("VMM stat is truncated")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return "", 0, fmt.Errorf("VMM stat start time is invalid")
	}
	return fields[0], value, nil
}

func parseStatus(reader io.Reader) (statusFields, error) {
	var result statusFields
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Uid":
			values, err := parseFourIDs(value, "UID")
			if err != nil {
				return result, err
			}
			result.uids = values
			seen[key] = true
		case "Gid":
			values, err := parseFourIDs(value, "GID")
			if err != nil {
				return result, err
			}
			result.gids = values
			seen[key] = true
		case "Groups":
			for _, item := range strings.Fields(value) {
				parsed, err := strconv.ParseUint(item, 10, 32)
				if err != nil {
					return result, fmt.Errorf("parse VMM group: %w", err)
				}
				result.groups = append(result.groups, uint32(parsed))
			}
			seen[key] = true
		case "NoNewPrivs":
			if value != "0" && value != "1" {
				return result, fmt.Errorf("parse VMM no_new_privs")
			}
			result.noNewPrivs = value == "1"
			seen[key] = true
		case "Seccomp":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return result, fmt.Errorf("parse VMM seccomp: %w", err)
			}
			result.seccomp = parsed
			seen[key] = true
		case "Seccomp_filters":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return result, fmt.Errorf("parse VMM seccomp filters: %w", err)
			}
			result.seccompFilters = parsed
			seen[key] = true
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			parsed, err := strconv.ParseUint(value, 16, 64)
			if err != nil {
				return result, fmt.Errorf("parse VMM %s: %w", key, err)
			}
			switch key {
			case "CapInh":
				result.capInh = parsed
			case "CapPrm":
				result.capPrm = parsed
			case "CapEff":
				result.capEff = parsed
			case "CapBnd":
				result.capBnd = parsed
			case "CapAmb":
				result.capAmb = parsed
			}
			seen[key] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("scan VMM status: %w", err)
	}
	for _, key := range []string{"Uid", "Gid", "Groups", "NoNewPrivs", "Seccomp", "Seccomp_filters", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !seen[key] {
			return result, fmt.Errorf("VMM status lacks %s", key)
		}
	}
	return result, nil
}

func parseFourIDs(value, name string) ([4]uint32, error) {
	var result [4]uint32
	values := strings.Fields(value)
	if len(values) != 4 {
		return result, fmt.Errorf("VMM %ss are incomplete", name)
	}
	for index, item := range values {
		parsed, err := strconv.ParseUint(item, 10, 32)
		if err != nil {
			return result, fmt.Errorf("parse VMM %s: %w", name, err)
		}
		result[index] = uint32(parsed)
	}
	return result, nil
}

func equalGroups(left, right []uint32) bool {
	leftCopy := append([]uint32(nil), left...)
	rightCopy := append([]uint32(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	if len(leftCopy) != len(rightCopy) {
		return false
	}
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func deadProcessState(state string) bool {
	return state == "" || state == "Z" || state == "X" || state == "x"
}

func hashPath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open VMM executable for hashing: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash VMM executable: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func rejectSymlinkComponents(path string) error {
	if !canonicalAbsolute(path) {
		return fmt.Errorf("path is not canonical absolute")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink component %q is not allowed", current)
		}
	}
	return nil
}
