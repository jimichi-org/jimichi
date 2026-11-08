package scripts

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPortForwardListenerProcess(t *testing.T) {
	if os.Getenv("FORWARD_LISTENER") != "yes" {
		return
	}
	stand, client := os.Getenv("STAND"), os.Getenv("FORWARD_CLIENT")
	port := os.Getenv("FORWARD_PORT")
	if err := os.WriteFile(filepath.Join(stand, client+".forward.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "test listener cannot bind:", err)
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /card", func(w http.ResponseWriter, _ *http.Request) {
		gen, err := os.ReadFile(filepath.Join(stand, client+".gen"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "c25519:card-%s-%s\n", client, strings.TrimSpace(string(gen)))
	})
	mux.HandleFunc("PUT /contact", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gen, err := os.ReadFile(filepath.Join(stand, client+".gen"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		name := client + "." + strings.TrimSpace(string(gen)) + ".pinned"
		file, err := os.OpenFile(filepath.Join(stand, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, writeErr := fmt.Fprintf(file, "2026/11/08 12:00:01 contact pinned card_hash=%s role=initiator\n", digest(string(body)))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	fmt.Printf("Forwarding from 127.0.0.1:%s -> 9201\n", port)
	if err := http.Serve(listener, mux); err != nil {
		os.Exit(2)
	}
}

func TestIntroduceReleasesRealPortForwardsForNextRun(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl for the real loopback listeners")
	}
	shell, bin, stand := bash(t), t.TempDir(), t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	kubectl := strings.Replace(introduceKubectl,
		`    echo "Forwarding from 127.0.0.1:$port -> 9201"`,
		`    export FORWARD_LISTENER=yes FORWARD_CLIENT="$which" FORWARD_PORT="$port"
    exec "$FORWARD_TEST_EXECUTABLE" '-test.run=^TestPortForwardListenerProcess$'`, 1)
	for name, text := range map[string]string{"kubectl": kubectl, "jimichi": introduceJimichi} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, client := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(stand, client+".gen"), []byte("1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := consecutivePortBase(t)
	t.Cleanup(func() {
		for _, client := range []string{"a", "b"} {
			if pid := listenerPID(t, stand, client); pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	})
	for attempt := range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, shell, script(t, "introduce.sh"))
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"STAND="+stand, "KUBECTL_CALLS="+filepath.Join(stand, "calls"), "JIMICHI="+filepath.Join(bin, "jimichi"),
			"FORWARD_TEST_EXECUTABLE="+executable, "INTRODUCE_PAUSE=0", "INTRODUCE_PORT_BASE="+strconv.Itoa(base),
			"RESTART=no", "SUITE=c25519", "JIMICHI_CONTEXT=kind-forward-test")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil || !strings.Contains(string(output), "introduced client-a=") {
			t.Fatalf("introduction %d: %v: %s", attempt+1, err, output)
		}
		for i, client := range []string{"a", "b"} {
			pid := listenerPID(t, stand, client)
			if pid <= 0 || syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatalf("introduction %d left the real %s listener process alive or unreaped", attempt+1, client)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(base+i+1))
			if err != nil {
				t.Fatalf("introduction %d did not release %s port: %v", attempt+1, client, err)
			}
			listener.Close()
			if err := os.Remove(filepath.Join(stand, client+".forward.pid")); err != nil {
				t.Fatal(err)
			}
		}
	}
	calls, err := os.ReadFile(filepath.Join(stand, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "--context kind-forward-test -n jimichi port-forward") != 4 {
		t.Fatal("background forwards did not preserve the pinned context")
	}
}

func listenerPID(t *testing.T, stand, client string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stand, client+".forward.pid"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Error(err)
		return 0
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil || pid <= 0 {
		t.Error("invalid listener PID")
		return 0
	}
	return pid
}

func consecutivePortBase(t *testing.T) int {
	t.Helper()
	for range 20 {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := first.Addr().(*net.TCPAddr).Port
		if port == 65535 {
			first.Close()
			continue
		}
		second, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port+1))
		first.Close()
		if err == nil {
			second.Close()
			return port - 1
		}
	}
	t.Fatal("no consecutive loopback ports")
	return 0
}
