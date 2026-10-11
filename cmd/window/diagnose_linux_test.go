//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"window/internal/gate"
)

func TestDiagnosticPlansStayWithinReadOnlyAllowlist(t *testing.T) {
	for _, input := range [][]string{
		{"jobs", "saturn"},
		{"containers", "vault-prod"},
		{"logs", "vault-prod-worker-1", "100"},
		{"inspect", "vault-prod-api-1", "vault-prod-worker-1", "vault-prod-web-1"},
		{"migrations"},
	} {
		if _, err := planDiagnostic(input); err != nil {
			t.Fatalf("expected %q to be permitted: %v", input, err)
		}
	}
	for _, input := range [][]string{
		{"docker", "run", "--privileged"},
		{"logs", "other-container"},
		{"logs", "vault-prod-secret-runtime-init-1"},
		{"logs", "vault-prod-worker-1", "201"},
		{"logs", "vault-prod-worker-1", "--follow"},
		{"logs", "vault-prod-worker-1;id"},
		{"inspect", "--format={{json .Config.Env}}", "vault-prod-worker-1"},
		{"inspect", "vault-prod-worker-1", "unrelated"},
		{"migrations", "DROP TABLE important"},
		{"jobs", "saturn;id"},
	} {
		if _, err := planDiagnostic(input); err == nil {
			t.Fatalf("unexpectedly permitted %q", input)
		}
	}
	inspect, _ := planDiagnostic([]string{"inspect", "vault-prod-worker-1"})
	if strings.Contains(strings.Join(inspect.args, " "), ".Config.Env") {
		t.Fatal("inspect includes container environment")
	}
	migrations, _ := planDiagnostic([]string{"migrations"})
	if !strings.Contains(strings.Join(migrations.args, " "), "BEGIN READ ONLY") || migrations.args[2] != "vault-prod-postgres-1" {
		t.Fatal("migration profile is not fixed and read-only")
	}
}

func TestDiagnosticContainerInventoryAndOutputAreBounded(t *testing.T) {
	data := []byte("vault-prod-worker-1\tUp 2 hours\nother-container\tUp 3 hours\nexocortex-kernel\tExited (0)\n")
	if got := string(managedContainers(data, "vault-prod")); got != "vault-prod-worker-1 Up 2 hours\n" {
		t.Fatalf("unexpected project inventory: %q", got)
	}
	if got := string(managedContainers(data, "")); strings.Contains(got, "other-container") || !strings.Contains(got, "exocortex-kernel") {
		t.Fatalf("unexpected managed inventory: %q", got)
	}
	filtered := filterDiagnosticOutput([]byte("normal\nAuthorization: Bearer synthetic\n\x1b[31mcolored\x1b[0m\n"))
	if !strings.Contains(filtered, "normal\ncolored\n") || strings.Contains(filtered, "synthetic") || !strings.Contains(filtered, "1 lines omitted") {
		t.Fatalf("unsafe diagnostic output: %q", filtered)
	}
}

func TestDiagnosticRequiresLiveGrantBeforeAndAfterRead(t *testing.T) {
	plan, _ := planDiagnostic([]string{"logs", "vault-prod-worker-1"})
	denied := errors.New("Window grant closed")
	called := 0
	run := func(context.Context, string, ...string) ([]byte, error) {
		called++
		return []byte("sensitive diagnostic result\n"), nil
	}
	jobs := func(context.Context, string) ([]byte, error) { t.Fatal("unexpected jobs read"); return nil, nil }
	data, err := executeDiagnostic(context.Background(), plan, func() error { return denied }, run, jobs)
	if !errors.Is(err, denied) || data != nil || called != 0 {
		t.Fatalf("closed grant started read: data=%q err=%v calls=%d", data, err, called)
	}
	checks := 0
	data, err = executeDiagnostic(context.Background(), plan, func() error {
		checks++
		if checks == 2 {
			return denied
		}
		return nil
	}, run, jobs)
	if !errors.Is(err, denied) || data != nil || called != 1 || checks != 2 {
		t.Fatalf("revoked grant leaked result: data=%q err=%v calls=%d checks=%d", data, err, called, checks)
	}
}

func TestDiagnosticJobsFilterServiceAndSecretMarkedFields(t *testing.T) {
	data, err := selectDiagnosticJobs([]gate.Job{
		{ID: "saturn-job", HeadID: "saturn", Summary: "token=synthetic"},
		{ID: "kernel-job", HeadID: "kernel", Summary: "healthy"},
	}, "saturn")
	if err != nil {
		t.Fatal(err)
	}
	var jobs []gate.Job
	if err := json.Unmarshal(data, &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != "saturn-job" || strings.Contains(jobs[0].Summary, "synthetic") {
		t.Fatalf("unsafe jobs view: %s", data)
	}
}
