package hostidentity

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

type fakeSystem struct {
	users    map[string]passwdEntry
	groups   map[string]groupEntry
	locked   map[string]bool
	kvm      int
	commands [][]string
}

func newFake(kvm int) *fakeSystem {
	return &fakeSystem{users: map[string]passwdEntry{}, groups: map[string]groupEntry{}, locked: map[string]bool{}, kvm: kvm}
}
func (f *fakeSystem) LookupUser(_ context.Context, s string) (passwdEntry, bool, error) {
	v, ok := f.users[s]
	return v, ok, nil
}
func (f *fakeSystem) LookupUID(_ context.Context, id int) (passwdEntry, bool, error) {
	for _, v := range f.users {
		if v.UID == id {
			return v, true, nil
		}
	}
	return passwdEntry{}, false, nil
}
func (f *fakeSystem) LookupGroup(_ context.Context, s string) (groupEntry, bool, error) {
	v, ok := f.groups[s]
	return v, ok, nil
}
func (f *fakeSystem) LookupGID(_ context.Context, id int) (groupEntry, bool, error) {
	for _, v := range f.groups {
		if v.GID == id {
			return v, true, nil
		}
	}
	return groupEntry{}, false, nil
}
func (f *fakeSystem) Groups(_ context.Context, s string) ([]int, error) {
	if _, ok := f.users[s]; !ok {
		return nil, fmt.Errorf("missing")
	}
	return []int{f.kvm}, nil
}
func (f *fakeSystem) PasswordLocked(_ context.Context, s string) (bool, error) {
	return f.locked[s], nil
}
func (f *fakeSystem) Run(_ context.Context, path string, args ...string) error {
	f.commands = append(f.commands, append([]string{path}, args...))
	name := args[len(args)-1]
	switch path {
	case "/usr/sbin/groupadd":
		id := mustInt(args[2])
		f.groups[name] = groupEntry{Name: name, GID: id}
	case "/usr/sbin/useradd":
		uid := mustInt(args[2])
		gid := mustInt(args[4])
		f.users[name] = passwdEntry{Name: name, UID: uid, GID: gid, Home: "/nonexistent", Shell: "/usr/sbin/nologin"}
	case "/usr/sbin/usermod":
		f.locked[name] = true
	case "/usr/sbin/userdel":
		delete(f.users, name)
		delete(f.locked, name)
	case "/usr/sbin/groupdel":
		delete(f.groups, name)
	}
	return nil
}
func mustInt(s string) int { var v int; fmt.Sscan(s, &v); return v }

func TestCandidateDeterministicBounded(t *testing.T) {
	one, err := Candidate("mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", 108, 0)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Candidate("mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", 108, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one, two) || len(one.Username) > 31 || one.Username != one.Groupname || one.UID != one.GID {
		t.Fatalf("candidate %+v %+v", one, two)
	}
}
func TestEnsureAdoptRemoveAndCollision(t *testing.T) {
	ctx := context.Background()
	fake := newFake(108)
	authority := Authority{System: fake}
	identity, err := authority.Plan(ctx, "mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", 108)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := authority.Ensure(ctx, identity)
	if err != nil || !observation.PasswordLocked {
		t.Fatalf("ensure %+v %v", observation, err)
	}
	if _, err := authority.Ensure(ctx, identity); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	fake.users[identity.Username] = passwdEntry{Name: identity.Username, UID: identity.UID + 1, GID: identity.GID, Home: identity.Home, Shell: identity.Shell}
	if _, err := authority.Observe(ctx, identity); err == nil {
		t.Fatal("wrong UID accepted")
	}
	fake.users[identity.Username] = passwdEntry{Name: identity.Username, UID: identity.UID, GID: identity.GID, Home: identity.Home, Shell: identity.Shell}
	if err := authority.Remove(ctx, identity); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := fake.LookupUID(ctx, identity.UID); found {
		t.Fatal("UID remains")
	}
}
func TestPlanSkipsNumericCollisionAndRefusesNameCollision(t *testing.T) {
	ctx := context.Background()
	fake := newFake(108)
	authority := Authority{System: fake}
	first, _ := Candidate("mach_baaaaaaaaaaaaaaaaaaaaaaaaa", 108, 0)
	fake.users["other"] = passwdEntry{Name: "other", UID: first.UID, GID: 999}
	planned, err := authority.Plan(ctx, first.MachineID, 108)
	if err != nil {
		t.Fatal(err)
	}
	if planned.UID == first.UID {
		t.Fatal("numeric collision reused")
	}
	fake.users[first.Username] = passwdEntry{Name: first.Username, UID: first.UID + 2, GID: first.GID + 2, Home: "/", Shell: "/bin/bash"}
	if _, err := authority.Plan(ctx, first.MachineID, 108); err == nil {
		t.Fatal("name collision accepted")
	}
}
