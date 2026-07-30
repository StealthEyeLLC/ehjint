// Package repositorycheck enforces deterministic EHJINT repository policy
// without relying on a private service or network lookup.
package repositorycheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const (
	modulePath         = "github.com/StealthEyeLLC/ehjint"
	maximumTrackedSize = int64(2 * 1024 * 1024)
)

var (
	gitDigestPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	actionPattern    = regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*uses:[ \t]*['"]?([^'"[:space:]#]+)`)
	credentialURL    = regexp.MustCompile(`https?://[^/[:space:]:@]+:[^/[:space:]@]+@`)
	awsAccessKey     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
)

// Finding is one deterministic policy violation.
type Finding struct {
	Check   string
	Path    string
	Message string
}

// Report records successful repository-check coverage.
type Report struct {
	FileCount int
	Checks    []string
}

// FindingsError reports every detected violation in deterministic order.
type FindingsError []Finding

func (findings FindingsError) Error() string {
	ordered := append(FindingsError(nil), findings...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Check != ordered[j].Check {
			return ordered[i].Check < ordered[j].Check
		}
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Message < ordered[j].Message
	})
	var output strings.Builder
	fmt.Fprintf(&output, "%d repository policy violation(s)", len(ordered))
	for _, finding := range ordered {
		fmt.Fprintf(&output, "\n- [%s] %s: %s", finding.Check, finding.Path, finding.Message)
	}
	return output.String()
}

// Check validates all tracked and non-ignored implementation files.
func Check(root string) (Report, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve repository root: %w", err)
	}
	files, err := repositoryFiles(absoluteRoot)
	if err != nil {
		return Report{}, err
	}
	findings := make([]Finding, 0)
	findings = append(findings, checkRequiredFiles(files)...)
	findings = append(findings, checkFileContent(absoluteRoot, files)...)
	findings = append(findings, checkGoModuleAndImports(absoluteRoot, files)...)
	findings = append(findings, checkDependencyAndWorkflowAgreement(absoluteRoot, files)...)
	findings = append(findings, checkRuntimeShape(files)...)
	findings = append(findings, checkEvidenceShape(files)...)
	if len(findings) != 0 {
		return Report{}, FindingsError(findings)
	}
	return Report{
		FileCount: len(files),
		Checks: []string{
			"required_files",
			"path_hygiene",
			"large_files",
			"tracked_binaries",
			"secret_patterns",
			"private_execution_leakage",
			"locked_go_imports",
			"dependency_locks",
			"immutable_ci_actions",
			"minimal_ci_authority",
			"single_runtime_entrypoint",
			"evidence_shape",
		},
	}, nil
}

func repositoryFiles(root string) ([]string, error) {
	command := exec.Command("git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("enumerate repository files: %w", err)
	}
	parts := bytes.Split(output, []byte{0})
	files := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		path := filepath.ToSlash(string(part))
		if filepath.IsAbs(path) || path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsRune(path, '\x00') {
			return nil, fmt.Errorf("unsafe repository path %q", path)
		}
		if seen[path] {
			return nil, fmt.Errorf("duplicate repository path %q", path)
		}
		seen[path] = true
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func checkRequiredFiles(files []string) []Finding {
	required := []string{
		".github/workflows/mission-1.yml",
		"api/generated-manifest.json",
		"api/mcp-tools.json",
		"cmd/ehjint/main.go",
		"config/compatibility.json",
		"config/dependencies.lock.json",
		"config/provider-contracts.json",
		"config/toolchain.lock.json",
		"docs/MISSION-1.md",
		"go.mod",
		"go.sum",
		"registry/operations.json",
		"scripts/bootstrap-tools.sh",
		"scripts/build.sh",
		"scripts/check-generated.sh",
		"scripts/check-repository.sh",
		"scripts/check.sh",
		"scripts/generate.sh",
		"scripts/test-cli.sh",
	}
	present := make(map[string]bool, len(files))
	for _, path := range files {
		present[path] = true
	}
	findings := make([]Finding, 0)
	for _, path := range required {
		if !present[path] {
			findings = append(findings, Finding{Check: "required_files", Path: path, Message: "required repository file is missing"})
		}
	}
	return findings
}

func checkFileContent(root string, files []string) []Finding {
	findings := make([]Finding, 0)
	for _, relative := range files {
		if strings.Contains(relative, "\\") || strings.HasPrefix(relative, ".cache/") || strings.HasPrefix(relative, "build/") {
			findings = append(findings, Finding{Check: "path_hygiene", Path: relative, Message: "generated cache/build path must not be tracked"})
			continue
		}
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(absolute)
		if err != nil {
			findings = append(findings, Finding{Check: "path_hygiene", Path: relative, Message: "cannot inspect file: " + err.Error()})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{Check: "path_hygiene", Path: relative, Message: "tracked symbolic links are forbidden"})
			continue
		}
		if !info.Mode().IsRegular() {
			findings = append(findings, Finding{Check: "path_hygiene", Path: relative, Message: "tracked path is not a regular file"})
			continue
		}
		if info.Size() > maximumTrackedSize {
			findings = append(findings, Finding{Check: "large_files", Path: relative, Message: fmt.Sprintf("size %d exceeds %d bytes", info.Size(), maximumTrackedSize)})
			continue
		}
		content, err := os.ReadFile(absolute)
		if err != nil {
			findings = append(findings, Finding{Check: "path_hygiene", Path: relative, Message: "cannot read file: " + err.Error()})
			continue
		}
		if bytes.HasPrefix(content, []byte{0x7f, 'E', 'L', 'F'}) || bytes.IndexByte(content, 0) >= 0 {
			findings = append(findings, Finding{Check: "tracked_binaries", Path: relative, Message: "binary content must be built from source, not tracked"})
			continue
		}
		findings = append(findings, scanSensitive(relative, content)...)
	}
	return findings
}

func scanSensitive(path string, content []byte) []Finding {
	patterns := []struct {
		check   string
		label   string
		literal string
	}{
		{"secret_patterns", "generic private key PEM", "-----BEGIN " + "PRIVATE KEY-----"},
		{"secret_patterns", "RSA private key PEM", "-----BEGIN RSA " + "PRIVATE KEY-----"},
		{"secret_patterns", "OpenSSH private key PEM", "-----BEGIN OPENSSH " + "PRIVATE KEY-----"},
		{"secret_patterns", "GitHub personal token prefix", "gh" + "p_"},
		{"secret_patterns", "GitHub application token prefix", "gh" + "s_"},
		{"secret_patterns", "GitHub OAuth token prefix", "gh" + "o_"},
		{"secret_patterns", "GitHub user token prefix", "gh" + "u_"},
		{"secret_patterns", "GitHub refresh token prefix", "gh" + "r_"},
		{"secret_patterns", "GitHub fine-grained token prefix", "github_" + "pat_"},
		{"secret_patterns", "Slack token prefix", "xo" + "xb-"},
		{"secret_patterns", "Slack token prefix", "xo" + "xp-"},
		{"private_execution_leakage", "private executor product", "baby" + "-quirt"},
		{"private_execution_leakage", "private executor operation", "call_" + "quirt"},
		{"private_execution_leakage", "private executor state path", "/" + "var/lib/" + "baby" + "-quirt"},
		{"private_execution_leakage", "private executor runtime path", "/" + "run/" + "baby" + "-quirt"},
		{"private_execution_leakage", "private installed executor path", "/" + "opt/baby"},
		{"private_execution_leakage", "interactive private terminal product", "Ter" + "mius"},
	}
	findings := make([]Finding, 0)
	for _, pattern := range patterns {
		if bytes.Contains(content, []byte(pattern.literal)) {
			findings = append(findings, Finding{Check: pattern.check, Path: path, Message: "contains " + pattern.label})
		}
	}
	if credentialURL.Match(content) {
		findings = append(findings, Finding{Check: "secret_patterns", Path: path, Message: "contains credentials embedded in a URL"})
	}
	if awsAccessKey.Match(content) {
		findings = append(findings, Finding{Check: "secret_patterns", Path: path, Message: "contains an AWS access-key-shaped value"})
	}
	return findings
}

func checkGoModuleAndImports(root string, files []string) []Finding {
	const check = "locked_go_imports"
	findings := make([]Finding, 0)
	dependencyData, err := os.ReadFile(filepath.Join(root, "config", "dependencies.lock.json"))
	if err != nil {
		return append(findings, Finding{Check: check, Path: "config/dependencies.lock.json", Message: "cannot read dependency lock: " + err.Error()})
	}
	dependencies, err := contracts.ParseDependencyLock(dependencyData)
	if err != nil {
		return append(findings, Finding{Check: check, Path: "config/dependencies.lock.json", Message: "cannot parse dependency lock: " + err.Error()})
	}
	locked := make(map[string]string)
	for _, dependency := range dependencies.Dependencies {
		if strings.HasPrefix(dependency.Source, "https://proxy.golang.org/") && strings.Contains(strings.Split(dependency.Name, "/")[0], ".") {
			locked[dependency.Name] = dependency.Version
		}
	}

	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return append(findings, Finding{Check: check, Path: "go.mod", Message: "cannot read go.mod: " + err.Error()})
	}
	requirements := make(map[string]string)
	moduleSeen := false
	goSeen := false
	inRequireBlock := false
	parseRequirement := func(line string) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "require directive must contain exactly module and version: " + strconv.Quote(line)})
			return
		}
		module, version := fields[0], fields[1]
		if _, exists := requirements[module]; exists {
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "duplicate module requirement " + strconv.Quote(module)})
			return
		}
		requirements[module] = version
		lockedVersion, exists := locked[module]
		if !exists {
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "module is not present in the dependency lock: " + module})
			return
		}
		if version != lockedVersion {
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: fmt.Sprintf("module %s version %s differs from locked version %s", module, version, lockedVersion)})
		}
	}
	for _, raw := range strings.Split(string(goMod), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			parseRequirement(line)
			continue
		}
		switch {
		case line == "module "+modulePath:
			moduleSeen = true
		case line == "go 1.26.0":
			goSeen = true
		case line == "require (":
			inRequireBlock = true
		case strings.HasPrefix(line, "require "):
			parseRequirement(strings.TrimSpace(strings.TrimPrefix(line, "require ")))
		case strings.HasPrefix(line, "replace "), strings.HasPrefix(line, "exclude "), strings.HasPrefix(line, "toolchain "):
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "replace, exclude, and toolchain directives are forbidden; use exact dependency and toolchain locks"})
		default:
			findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "unexpected directive " + strconv.Quote(line)})
		}
	}
	if inRequireBlock {
		findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "unterminated require block"})
	}
	if !moduleSeen || !goSeen {
		findings = append(findings, Finding{Check: check, Path: "go.mod", Message: "module path or exact Go language version is missing"})
	}

	goSumPresent := false
	for _, relative := range files {
		if relative == "go.sum" {
			goSumPresent = true
		}
		if !strings.HasSuffix(relative, ".go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(relative)), nil, parser.ImportsOnly)
		if parseErr != nil {
			findings = append(findings, Finding{Check: check, Path: relative, Message: "cannot parse Go imports: " + parseErr.Error()})
			continue
		}
		for _, specification := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(specification.Path.Value)
			if unquoteErr != nil {
				findings = append(findings, Finding{Check: check, Path: relative, Message: "invalid import literal"})
				continue
			}
			if importPath == "C" {
				findings = append(findings, Finding{Check: check, Path: relative, Message: "direct cgo imports are forbidden outside locked dependencies"})
				continue
			}
			first := strings.Split(importPath, "/")[0]
			if !strings.Contains(first, ".") || importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/") {
				continue
			}
			matched := false
			for module := range requirements {
				if importPath == module || strings.HasPrefix(importPath, module+"/") {
					matched = true
					break
				}
			}
			if !matched {
				findings = append(findings, Finding{Check: check, Path: relative, Message: "external Go import " + strconv.Quote(importPath) + " is not an exact locked requirement"})
			}
		}
	}
	if len(requirements) != 0 && !goSumPresent {
		findings = append(findings, Finding{Check: check, Path: "go.sum", Message: "go.sum is required for locked Go modules"})
	}
	if len(requirements) == 0 && goSumPresent {
		findings = append(findings, Finding{Check: check, Path: "go.sum", Message: "go.sum is unexpected without Go module requirements"})
	}
	if goSumPresent {
		findings = append(findings, checkGoSum(root, requirements)...)
	}
	return findings
}

func checkGoSum(root string, requirements map[string]string) []Finding {
	const check = "locked_go_imports"
	data, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return []Finding{{Check: check, Path: "go.sum", Message: "cannot read go.sum: " + err.Error()}}
	}
	seen := make(map[string]bool)
	findings := make([]Finding, 0)
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			findings = append(findings, Finding{Check: check, Path: "go.sum", Message: fmt.Sprintf("line %d must contain exactly module, version, and sum", lineNumber+1)})
			continue
		}
		module, version, sum := fields[0], fields[1], fields[2]
		lockedVersion, exists := requirements[module]
		if !exists {
			findings = append(findings, Finding{Check: check, Path: "go.sum", Message: "sum exists for an undeclared module: " + module})
			continue
		}
		if version != lockedVersion && version != lockedVersion+"/go.mod" {
			findings = append(findings, Finding{Check: check, Path: "go.sum", Message: fmt.Sprintf("sum version %s for %s differs from required version %s", version, module, lockedVersion)})
			continue
		}
		encoded := strings.TrimPrefix(sum, "h1:")
		decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if !strings.HasPrefix(sum, "h1:") || decodeErr != nil || len(decoded) != sha256.Size {
			findings = append(findings, Finding{Check: check, Path: "go.sum", Message: fmt.Sprintf("line %d has an invalid h1 module sum", lineNumber+1)})
			continue
		}
		key := module + " " + version
		if seen[key] {
			findings = append(findings, Finding{Check: check, Path: "go.sum", Message: "duplicate sum entry: " + key})
			continue
		}
		seen[key] = true
	}
	for module, version := range requirements {
		for _, required := range []string{module + " " + version, module + " " + version + "/go.mod"} {
			if !seen[required] {
				findings = append(findings, Finding{Check: check, Path: "go.sum", Message: "missing exact sum entry: " + required})
			}
		}
	}
	return findings
}

func checkDependencyAndWorkflowAgreement(root string, files []string) []Finding {
	findings := make([]Finding, 0)
	dependencyData, err := os.ReadFile(filepath.Join(root, "config", "dependencies.lock.json"))
	if err != nil {
		return append(findings, Finding{Check: "dependency_locks", Path: "config/dependencies.lock.json", Message: err.Error()})
	}
	dependencies, err := contracts.ParseDependencyLock(dependencyData)
	if err != nil {
		return append(findings, Finding{Check: "dependency_locks", Path: "config/dependencies.lock.json", Message: err.Error()})
	}
	toolchainData, err := os.ReadFile(filepath.Join(root, "config", "toolchain.lock.json"))
	if err != nil {
		return append(findings, Finding{Check: "dependency_locks", Path: "config/toolchain.lock.json", Message: err.Error()})
	}
	toolchain, err := contracts.ParseToolchainLock(toolchainData)
	if err != nil {
		return append(findings, Finding{Check: "dependency_locks", Path: "config/toolchain.lock.json", Message: err.Error()})
	}
	if err := contracts.VerifyToolchainDependencyAgreement(toolchain, dependencies); err != nil {
		findings = append(findings, Finding{Check: "dependency_locks", Path: "config", Message: err.Error()})
	}

	expectedActions := make(map[string]bool)
	for _, dependency := range dependencies.Dependencies {
		if dependency.Scope != "ci" {
			continue
		}
		if !strings.HasPrefix(dependency.Source, "https://github.com/") || !strings.HasPrefix(dependency.Digest, "git:") {
			findings = append(findings, Finding{Check: "dependency_locks", Path: "config/dependencies.lock.json", Message: "CI dependency " + dependency.Name + " must bind an official GitHub source to a Git commit"})
			continue
		}
		repository := strings.TrimPrefix(dependency.Source, "https://github.com/")
		commit := strings.TrimPrefix(dependency.Digest, "git:")
		if !gitDigestPattern.MatchString(commit) {
			findings = append(findings, Finding{Check: "dependency_locks", Path: "config/dependencies.lock.json", Message: "CI dependency " + dependency.Name + " has an invalid commit digest"})
			continue
		}
		expectedActions[repository+"@"+commit] = false
	}

	workflowCount := 0
	for _, relative := range files {
		if !strings.HasPrefix(relative, ".github/workflows/") || (!strings.HasSuffix(relative, ".yml") && !strings.HasSuffix(relative, ".yaml")) {
			continue
		}
		workflowCount++
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			findings = append(findings, Finding{Check: "minimal_ci_authority", Path: relative, Message: err.Error()})
			continue
		}
		text := string(content)
		for _, forbidden := range []string{"pull_request_target:", "workflow_run:", "secrets.", "id-token: write", "contents: write", "sudo "} {
			if strings.Contains(text, forbidden) {
				findings = append(findings, Finding{Check: "minimal_ci_authority", Path: relative, Message: "contains forbidden CI authority " + strconv.Quote(forbidden)})
			}
		}
		for _, required := range []string{"permissions:", "contents: read", "runs-on: ubuntu-24.04", "timeout-minutes:", "persist-credentials: false", "./scripts/bootstrap-tools.sh", "./scripts/check.sh"} {
			if !strings.Contains(text, required) {
				findings = append(findings, Finding{Check: "minimal_ci_authority", Path: relative, Message: "missing required minimal-CI declaration " + strconv.Quote(required)})
			}
		}
		matches := actionPattern.FindAllStringSubmatch(text, -1)
		if len(matches) == 0 {
			findings = append(findings, Finding{Check: "immutable_ci_actions", Path: relative, Message: "workflow contains no action reference"})
		}
		for _, match := range matches {
			reference := match[1]
			if strings.HasPrefix(reference, "./") {
				continue
			}
			at := strings.LastIndex(reference, "@")
			if at <= 0 || !gitDigestPattern.MatchString(reference[at+1:]) {
				findings = append(findings, Finding{Check: "immutable_ci_actions", Path: relative, Message: "action is not pinned to a full lowercase Git commit: " + reference})
				continue
			}
			if _, ok := expectedActions[reference]; !ok {
				findings = append(findings, Finding{Check: "dependency_locks", Path: relative, Message: "action is not present with the same digest in the dependency lock: " + reference})
				continue
			}
			expectedActions[reference] = true
		}
	}
	if workflowCount != 1 {
		findings = append(findings, Finding{Check: "minimal_ci_authority", Path: ".github/workflows", Message: fmt.Sprintf("expected exactly one workflow, found %d", workflowCount)})
	}
	for reference, used := range expectedActions {
		if !used {
			findings = append(findings, Finding{Check: "dependency_locks", Path: "config/dependencies.lock.json", Message: "locked CI action is unused: " + reference})
		}
	}
	return findings
}

func checkRuntimeShape(files []string) []Finding {
	findings := make([]Finding, 0)
	commands := make([]string, 0)
	for _, path := range files {
		if strings.HasPrefix(path, "cmd/") {
			commands = append(commands, path)
		}
	}
	if len(commands) != 1 || commands[0] != "cmd/ehjint/main.go" {
		findings = append(findings, Finding{Check: "single_runtime_entrypoint", Path: "cmd", Message: "EHJINT must contain exactly cmd/ehjint/main.go as the runtime entrypoint"})
	}
	return findings
}

func checkEvidenceShape(files []string) []Finding {
	allowed := map[string]bool{
		"evidence/mission-1/RESULT.md": true,
		"evidence/mission-2/RESULT.md": true,
	}
	seen := make(map[string]bool)
	findings := make([]Finding, 0)
	for _, path := range files {
		if !strings.HasPrefix(path, "evidence/") {
			continue
		}
		seen[path] = true
		if !allowed[path] {
			findings = append(findings, Finding{Check: "evidence_shape", Path: path, Message: "only the exact Mission 1 and Mission 2 RESULT.md evidence files are permitted"})
		}
	}
	if len(seen) != 0 && !seen["evidence/mission-1/RESULT.md"] {
		findings = append(findings, Finding{Check: "evidence_shape", Path: "evidence/mission-1/RESULT.md", Message: "Mission 1 evidence must remain present when repository evidence exists"})
	}
	return findings
}
