package repositorycheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSensitiveContentDetection(t *testing.T) {
	cases := map[string]string{
		"private key":      "-----BEGIN " + "PRIVATE KEY-----",
		"GitHub token":     "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
		"fine-grained PAT": "github_" + "pat_abcdefghijklmnopqrstuvwxyz",
		"credential URL":   "https://" + "user:password@" + "example.invalid/path",
		"AWS access key":   "AKIA" + "ABCDEFGHIJKLMNOP",
		"private path":     "/" + "var/lib/" + "baby" + "-quirt/example",
		"private executor": "baby" + "-quirt",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if findings := scanSensitive("sample.txt", []byte(content)); len(findings) == 0 {
				t.Fatal("sensitive content was not detected")
			}
		})
	}
	if findings := scanSensitive("safe.txt", []byte("official public source and digest only\n")); len(findings) != 0 {
		t.Fatalf("safe content produced findings: %+v", findings)
	}
}

func TestDeclaredEHJINTManagedPathsAreNotPrivateExecutorLeakage(t *testing.T) {
	for _, value := range []string{"/var/lib/ehjint", "/run/ehjint", "/opt/ehjint"} {
		for _, finding := range scanSensitive("safe.txt", []byte(value)) {
			if finding.Check == "private_execution_leakage" {
				t.Fatalf("declared EHJINT path %q was rejected: %+v", value, finding)
			}
		}
	}
}

func TestEvidenceShapeAllowsExactMissionResults(t *testing.T) {
	files := []string{"evidence/mission-1/RESULT.md", "evidence/mission-2/RESULT.md"}
	if findings := checkEvidenceShape(files); len(findings) != 0 {
		t.Fatalf("exact evidence shape rejected: %+v", findings)
	}
	if findings := checkEvidenceShape([]string{"evidence/mission-2/RESULT.md"}); len(findings) == 0 {
		t.Fatal("Mission 2 evidence without preserved Mission 1 evidence was accepted")
	}
	if findings := checkEvidenceShape(append(files, "evidence/mission-2/extra.txt")); len(findings) == 0 {
		t.Fatal("extra evidence file was accepted")
	}
}

func TestFindingsErrorDeterministic(t *testing.T) {
	findings := FindingsError{
		{Check: "z", Path: "b", Message: "two"},
		{Check: "a", Path: "c", Message: "one"},
	}
	message := findings.Error()
	if strings.Index(message, "[a]") > strings.Index(message, "[z]") {
		t.Fatalf("findings are not sorted: %s", message)
	}
}

func TestRepositoryFilesRejectIgnoredBuildOutput(t *testing.T) {
	root := t.TempDir()
	for _, command := range [][]string{{"git", "init", "-q", root}, {"git", "-C", root, "config", "user.email", "test@example.invalid"}, {"git", "-C", root, "config", "user.name", "Test"}} {
		if output, err := run(command...); err != nil {
			t.Fatalf("%v: %v: %s", command, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("/build/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build", "binary"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := repositoryFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasPrefix(path, "build/") {
			t.Fatalf("ignored build output was enumerated: %s", path)
		}
	}
}

func run(arguments ...string) ([]byte, error) {
	return exec.Command(arguments[0], arguments[1:]...).CombinedOutput()
}

func TestCurrentRepositoryPasses(t *testing.T) {
	report, err := Check(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.FileCount < 80 || len(report.Checks) != 12 {
		t.Fatalf("unexpected repository report: %+v", report)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
