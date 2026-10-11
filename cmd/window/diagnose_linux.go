//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"window/internal/gate"
)

const diagnosticLimit = 128 * 1024
const migrationQuery = "BEGIN READ ONLY; SELECT name FROM _vault_migrations ORDER BY name DESC LIMIT 3; SELECT to_regnamespace('_saturn_restore_guard') IS NOT NULL; COMMIT;"

var diagnosticService = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

type diagnosticPlan struct {
	kind    string
	filter  string
	command string
	args    []string
}

// These are fixed read operations, not a general Docker or SQL proxy.
func planDiagnostic(args []string) (diagnosticPlan, error) {
	usage := errors.New("usage: sudo window diagnose jobs [SERVICE] | containers [exocortex|vault-prod] | logs CONTAINER [1..200] | inspect CONTAINER [CONTAINER...] | migrations")
	if len(args) == 0 {
		return diagnosticPlan{}, usage
	}
	switch args[0] {
	case "jobs":
		if len(args) > 2 || len(args) == 2 && !diagnosticService.MatchString(args[1]) {
			return diagnosticPlan{}, usage
		}
		plan := diagnosticPlan{kind: "jobs"}
		if len(args) == 2 {
			plan.filter = args[1]
		}
		return plan, nil
	case "containers":
		if len(args) > 2 || len(args) == 2 && args[1] != "exocortex" && args[1] != "vault-prod" {
			return diagnosticPlan{}, usage
		}
		plan := diagnosticPlan{kind: "containers", command: "/usr/bin/docker", args: []string{"ps", "-a", "--format", "{{.Names}}\t{{.Status}}"}}
		if len(args) == 2 {
			plan.filter = args[1]
		}
		return plan, nil
	case "logs":
		if len(args) < 2 || len(args) > 3 || !gate.ManagedContainerName(args[1]) {
			return diagnosticPlan{}, usage
		}
		lines := 100
		if len(args) == 3 {
			var err error
			lines, err = strconv.Atoi(args[2])
			if err != nil || lines < 1 || lines > 200 {
				return diagnosticPlan{}, usage
			}
		}
		return diagnosticPlan{kind: "logs", command: "/usr/bin/docker", args: []string{"logs", "--timestamps", "--since=24h", "--tail=" + strconv.Itoa(lines), args[1]}}, nil
	case "inspect":
		if len(args) < 2 || len(args) > 6 {
			return diagnosticPlan{}, usage
		}
		for _, name := range args[1:] {
			if !gate.ManagedContainerName(name) {
				return diagnosticPlan{}, usage
			}
		}
		fixed := []string{"inspect", "--type=container", "--format", "{{.Name}} image={{.Config.Image}} status={{.State.Status}} error={{.State.Error}}"}
		return diagnosticPlan{kind: "inspect", command: "/usr/bin/docker", args: append(fixed, args[1:]...)}, nil
	case "migrations":
		if len(args) != 1 {
			return diagnosticPlan{}, usage
		}
		return diagnosticPlan{kind: "migrations", command: "/usr/bin/docker", args: []string{
			"exec", "--env=PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000",
			"vault-prod-postgres-1", "psql", "-X", "-U", "vault", "-d", "vault", "-v", "ON_ERROR_STOP=1", "-Atc", migrationQuery,
		}}, nil
	default:
		return diagnosticPlan{}, usage
	}
}

func diagnosticStatus() error {
	var status struct {
		Open bool `json:"open"`
		Live bool `json:"live"`
	}
	if err := adminRequest(context.Background(), "GET", "/v1/status", nil, &status); err != nil {
		return err
	}
	if !status.Open || !status.Live {
		return errors.New("open a Window grant and start the observed operator shell first")
	}
	return nil
}

func diagnose(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("diagnostics require the restricted windowops sudo rule")
	}
	operator, err := user.Lookup("windowops")
	if err != nil || os.Getenv("SUDO_UID") != operator.Uid {
		return errors.New("diagnostics must be started by windowops through sudo")
	}
	plan, err := planDiagnostic(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	data, err := executeDiagnostic(ctx, plan, diagnosticStatus, runDiagnostic, diagnosticJobs)
	if len(data) > 0 {
		fmt.Fprint(os.Stdout, filterDiagnosticOutput(data))
	}
	if err != nil {
		return fmt.Errorf("%s diagnostic failed: %w", plan.kind, err)
	}
	return nil
}

func executeDiagnostic(ctx context.Context, plan diagnosticPlan, check func() error,
	run func(context.Context, string, ...string) ([]byte, error),
	jobs func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if err := check(); err != nil {
		return nil, err
	}
	var data []byte
	var err error
	if plan.kind == "jobs" {
		data, err = jobs(ctx, plan.filter)
	} else {
		data, err = run(ctx, plan.command, plan.args...)
		if plan.kind == "containers" {
			data = managedContainers(data, plan.filter)
		}
	}
	// Buffer everything until the grant and live shell have been checked again.
	// A revoke during a command therefore suppresses its entire result.
	if checkErr := check(); checkErr != nil {
		return nil, checkErr
	}
	return data, err
}

type diagnosticBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *diagnosticBuffer) Write(data []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.Len()+len(data) > diagnosticLimit {
		return 0, errors.New("diagnostic output exceeded its limit")
	}
	return b.Buffer.Write(data)
}

func runDiagnostic(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent", "DOCKER_HOST=unix:///var/run/docker.sock", "LC_ALL=C"}
	output := &diagnosticBuffer{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	return output.Bytes(), err
}

func managedContainers(data []byte, project string) []byte {
	var selected strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		name, status, found := strings.Cut(line, "\t")
		if found && gate.ManagedContainerName(name) && (project == "" || strings.HasPrefix(name, project+"-")) {
			selected.WriteString(name + " " + status + "\n")
		}
	}
	return []byte(selected.String())
}

func filterDiagnosticOutput(data []byte) string {
	var output strings.Builder
	omitted := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		clean, drop := gate.Filter(line)
		if drop {
			omitted++
			continue
		}
		if output.Len()+len(clean)+1 > gate.MaxReadBytes {
			output.WriteString("[diagnostic output truncated]\n")
			break
		}
		output.WriteString(clean + "\n")
	}
	if omitted > 0 {
		fmt.Fprintf(&output, "[%d lines omitted by Window filter]\n", omitted)
	}
	return output.String()
}

func diagnosticJobs(ctx context.Context, service string) ([]byte, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", updaterSocket)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, "GET", "http://updater.local/v1/overview", nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Updater returned HTTP %d", response.StatusCode)
	}
	var view struct {
		Jobs []gate.Job `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 512*1024)).Decode(&view); err != nil {
		return nil, err
	}
	return selectDiagnosticJobs(view.Jobs, service)
}

func selectDiagnosticJobs(input []gate.Job, service string) ([]byte, error) {
	jobs := make([]gate.Job, 0, min(len(input), 100))
	for _, job := range input {
		if service != "" && job.HeadID != service && job.Component != service {
			continue
		}
		for _, field := range []*string{&job.ID, &job.HeadID, &job.Component, &job.State, &job.Version, &job.Summary} {
			clean, omitted := gate.Filter(*field)
			if omitted {
				clean = "[job field omitted by Window filter]"
			}
			*field = clean
		}
		jobs = append(jobs, job)
		if len(jobs) == 100 {
			break
		}
	}
	return json.MarshalIndent(jobs, "", "  ")
}
