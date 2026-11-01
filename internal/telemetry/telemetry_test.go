// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry/collectortest"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
)

const canary = "CANARY-7f3a9c"

func TestLoadTakesOnlyTrue(t *testing.T) {
	for _, v := range []string{"", "1", "TRUE", "yes"} {
		t.Setenv(telemetry.EnvLogs, v)
		t.Setenv(telemetry.EnvSkipVerify, v)
		if s := telemetry.Load(""); s.Logs || s.SkipVerify {
			t.Errorf("value %q turned a switch on: %+v", v, s)
		}
	}
	t.Setenv(telemetry.EnvLogs, "true")
	t.Setenv(telemetry.EnvSkipVerify, "true")
	if s := telemetry.Load(""); !s.Logs || !s.SkipVerify {
		t.Errorf("true left a switch off: %+v", s)
	}
}

func TestUnsetLeavesStdoutWriterAlone(t *testing.T) {
	s := telemetry.Settings{}
	if s.Output(os.Stdout) != os.Stdout {
		t.Fatal("logs off: Output must be stdout itself")
	}
	if len(s.Dependencies()) != 0 {
		t.Fatal("no endpoint: want no otlp dependency")
	}
}

func TestDependencyOnlyWithEndpoint(t *testing.T) {
	deps := telemetry.Settings{Endpoint: "http://collector.example:4317"}.Dependencies()
	if len(deps) != 1 || deps[0].Name != "otlp" || deps[0].Required {
		t.Fatalf("deps = %+v, want one optional otlp", deps)
	}
}

func TestCheck(t *testing.T) {
	early, late := time.Unix(100, 0), time.Unix(200, 0)
	bad := otel.SignalStatus{LastSuccess: early, LastErrorAt: late}
	good := otel.SignalStatus{LastSuccess: late, LastErrorAt: early}
	tests := []struct {
		name   string
		state  otel.ExportStatus
		logsOn bool
		fail   bool
	}{
		{name: "nothing yet"},
		{name: "recovered", state: otel.ExportStatus{Traces: good, Metrics: good}},
		{name: "traces", state: otel.ExportStatus{Traces: bad}, fail: true},
		{name: "metrics", state: otel.ExportStatus{Metrics: bad}, fail: true},
		{name: "logs off", state: otel.ExportStatus{Logs: bad}},
		{name: "logs on", state: otel.ExportStatus{Logs: bad}, logsOn: true, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := telemetry.Check(tt.state, tt.logsOn) != nil; got != tt.fail {
				t.Fatalf("failed = %v, want %v", got, tt.fail)
			}
		})
	}
}

func startLogs(t *testing.T, endpoint string) (telemetry.Settings, func()) {
	t.Helper()
	t.Setenv("LOG_FORMAT", "json")
	s := telemetry.Settings{Endpoint: endpoint, Logs: true}
	shutdown, err := otel.InitWithOptions(context.Background(), "connector", endpoint, s.Options()...)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return s, func() {
		if err := shutdown(context.Background()); err != nil {
			t.Logf("shutdown: %v", err)
		}
	}
}

func TestCanaryNeverReachesCollector(t *testing.T) {
	c := collectortest.Start(t, codes.OK)
	s, stop := startLogs(t, c.Endpoint)

	var stdout bytes.Buffer
	lg := log.NewLoggerWithOptions("connector", log.WithOutput(s.Output(&stdout)))
	lg.Warn("target refused",
		log.F("secret_id", "sec-1"),
		log.F("error_code", "Unavailable"),
		log.F("error", "bind failed for "+canary),
		log.F("detail", canary),
		log.F("reason", canary),
		log.F("token_file", canary),
		log.F("protocol", canary),
		log.F("stack", canary),
	)
	lg.Warn("token check", log.F("backoff", "snk_"+canary))
	stop()

	got := c.Text()
	if strings.Contains(got, canary) {
		t.Fatalf("canary exported: %s", got)
	}
	for _, want := range []string{"target refused", "sec-1", "Unavailable", "[string]"} {
		if !strings.Contains(got, want) {
			t.Errorf("export lacks %q: %s", want, got)
		}
	}
	if !strings.Contains(stdout.String(), canary) {
		t.Error("stdout must keep the full line")
	}
}

func TestZerologLinesAreExportedAndKeepStdout(t *testing.T) {
	c := collectortest.Start(t, codes.OK)
	s, stop := startLogs(t, c.Endpoint)

	var stdout bytes.Buffer
	l := s.Zerolog(zerolog.New(os.Stderr).With().Str("service", "connector").Logger(), &stdout)
	l.Info().Str("reason", canary).Msg("connector token reloaded")
	stop()

	if !strings.Contains(c.Text(), "connector token reloaded") {
		t.Fatalf("line not exported: %s", c.Text())
	}
	if strings.Contains(c.Text(), canary) {
		t.Fatal("canary exported")
	}
	if !strings.Contains(stdout.String(), `"service":"connector"`) {
		t.Fatalf("stdout lost its context: %s", stdout.String())
	}
}

func TestConsoleFormatKeepsItsWriter(t *testing.T) {
	t.Setenv("LOG_FORMAT", "console")
	var original, tee bytes.Buffer
	l := telemetry.Settings{Logs: true}.Zerolog(zerolog.New(&original), &tee)
	l.Info().Msg("hello")
	if original.Len() == 0 || tee.Len() != 0 {
		t.Fatalf("original %d bytes, tee %d bytes", original.Len(), tee.Len())
	}
}

func TestFailingCollectorDegradesAndStaysReady(t *testing.T) {
	c := collectortest.Start(t, codes.PermissionDenied)
	s, stop := startLogs(t, c.Endpoint)
	defer stop()

	lg := log.NewLoggerWithOptions("connector", log.WithOutput(s.Output(&bytes.Buffer{})))
	checker, err := server.NewChecker(log.Nop(), s.Dependencies(), health.WithTTL(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go checker.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		lg.Info("tick")
		rep := checker.Report(ctx)
		if rep.Status == health.StateDegraded {
			if !rep.Ready {
				t.Fatalf("degraded must stay ready: %+v", rep)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("never degraded")
}

func TestExportErrorHandlerHidesTextAndLimitsRate(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	var out bytes.Buffer
	h := telemetry.ExportErrorHandler(log.NewLoggerWithOptions("connector", log.WithOutput(&out)))
	h.Handle(errors.New("dial https://user:" + canary + "@collector.example:4317"))
	h.Handle(errors.New("again"))
	if strings.Contains(out.String(), canary) {
		t.Fatalf("error text logged: %s", out.String())
	}
	if n := strings.Count(out.String(), "otlp export failed"); n != 1 {
		t.Fatalf("logged %d lines, want 1", n)
	}
}
