package layout

import (
	"path/filepath"
	"testing"
)

func TestCanonicalLayout(t *testing.T) {
	paths := Canonical()
	checks := map[string]string{
		"opt": paths.Opt, "current": paths.Current, "bin": paths.Bin,
		"alias": paths.Alias, "etc": paths.Etc, "host": paths.HostConfig,
		"operator": paths.OperatorConfig, "state": paths.State, "database": paths.Database,
		"images": paths.Images, "machines": paths.Machines, "operations": paths.Operations,
		"downloads": paths.Downloads, "run": paths.Run, "socket": paths.ControllerSocket,
		"lock": paths.ControllerLock, "runtime_machines": paths.RuntimeMachines,
	}
	expected := map[string]string{
		"opt": OptRootCanonical, "current": CurrentCanonical, "bin": BinCanonical,
		"alias": AliasCanonical, "etc": EtcCanonical, "host": HostConfigCanonical,
		"operator": OperatorConfigCanonical, "state": StateCanonical, "database": DatabaseCanonical,
		"images": ImagesCanonical, "machines": MachinesCanonical, "operations": OperationsCanonical,
		"downloads": CacheCanonical, "run": RunCanonical, "socket": ControllerSocket,
		"lock": ControllerLock, "runtime_machines": RuntimeMachines,
	}
	for name, actual := range checks {
		if actual != expected[name] {
			t.Fatalf("%s: got %q want %q", name, actual, expected[name])
		}
	}
}

func TestUnderRootAndSafeJoin(t *testing.T) {
	root := t.TempDir()
	paths := UnderRoot(root)
	if paths.Database != filepath.Join(root, "var/lib/ehjint/controller.sqlite3") {
		t.Fatalf("unexpected rooted database: %s", paths.Database)
	}
	machine, err := paths.Machine("mach_example")
	if err != nil || machine != filepath.Join(root, "var/lib/ehjint/machines/mach_example") {
		t.Fatalf("unexpected machine path %q error %v", machine, err)
	}
	for _, bad := range []string{"", "..", "../escape", "/absolute", "a/../../escape", "nul\x00value"} {
		if _, err := SafeJoin(paths.Machines, bad); err == nil {
			t.Fatalf("unsafe element accepted: %q", bad)
		}
	}
}
