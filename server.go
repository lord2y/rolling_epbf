package main

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/lord2y/rolling_ebpf/compile"
	"github.com/prometheus/procfs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

func loadReuseportSelect(s *zap.SugaredLogger) *ebpf.Program {
	stateDir := "/sys/fs/bpf"
	collectionLocation := "./bpf/"

	if _, err := os.Stat(filepath.Join("./bpf/", "rolling_reuseport.o")); err != nil {
		if err := compile.CompileWithOptions(context.TODO(), "./bpf/rolling_reuseport.c", "./bpf/rolling_reuseport.o", []string{"-v", "-I", "./bpf/", "-I", "./bpf/include/"}); err != nil {
			s.Errorf("failed to compile bpf_rolling_reuseport.c %w", err)
		} else {
			s.Info("Compiled bpf_rolling_reuseport.o successfully !")
		}
	}
	var prog *ebpf.Program
	var coll *ebpf.Collection

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: stateDir,
		},
		Programs: ebpf.ProgramOptions{
			LogDisabled: false,
			LogSize:     ebpf.DefaultVerifierLogSize,
			LogLevel:    ebpf.LogLevelInstruction,
		},
	}

	spec, err := ebpf.LoadCollectionSpec(filepath.Join(collectionLocation, "rolling_reuseport.o"))
	if err != nil {
		s.Errorf("Unable to load at %s: %w", filepath.Join(collectionLocation, "rolling_reuseport.o"), err)
		return nil
	} else {
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			s.Errorf("failed to create eBPF collection: %w", err)
			return nil
		}
		prog = coll.Programs["hot_standby_selector"]
		if prog == nil {
			s.Error("program not found in collection\n")
			return nil
		}
	}
	return prog
}

func getListenConfig(prog *ebpf.Program, vers string, otherInstancesRunning bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// Set SO_REUSEPORT on the socket
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// Set eBPF program to be invoked for socket selection
			if prog != nil && vers == "v1.0.0" && !otherInstancesRunning {
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					opErr = fmt.Errorf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %w", err)
				} else {
					zap.S().Info("SO_REUSEPORT bpf prog attach completed successfully")
				}
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}}
	return lc
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	zap.S().Info("got /ping request\n")
	vers := os.Args[1]
	if vers == "v1.0.0" {
		io.WriteString(w, fmt.Sprintf("Demo SRE meeting W45 - %s\n", os.Args[1]))
	}else{
		io.WriteString(w, fmt.Sprintf("Demo SRE meeing W45 - %s!\n", os.Args[1]))
	}

}

// GetFdFromListener get net.Listener's file descriptor.
func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func main() {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig = zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "level",
		TimeKey:        "time",
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller: func(caller zapcore.EntryCaller, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString("")
		}}
	logger, _ := cfg.Build()
	s := logger.Sugar()
	vers := os.Args[1]
	if vers != "v1.0.0" && vers != "v1.0.1" {
		s.Infof("Server vers should either be v1.0.0 or v1.0.1")
		return
	}
	s.Infof("Starting server %s", vers)
	prog := loadReuseportSelect(s)

	http.HandleFunc("/ping", handleHello)
	server := http.Server{Addr: "127.0.0.1:8000", Handler: nil}
	fs, _ := procfs.NewDefaultFS()
	netTCP, _ := fs.NetTCP()

	otherInstancesRunning := false
	for _, i := range netTCP {
		if i.LocalPort == 8000 {
			otherInstancesRunning = true
			break
		}
	}

	lc := getListenConfig(prog, vers, otherInstancesRunning)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		s.Fatalf("Unable to listen of specified addr %w", err)
	} else {
		s.Infof("Started listening in 127.0.0.1:8000 successfully !")
	}

	stateDir := "/sys/fs/bpf"
	mapName := "tcp_balancing_targets"

	var k uint32
	if vers == "v1.0.0" {
		k = uint32(0)
	} else {
		k = uint32(1)
	}
	v := uint64(GetFdFromListener(ln))
	s.Infof("Updating with k=%d v=%d", k, v)
	m, err := ebpf.LoadPinnedMap(filepath.Join(stateDir, mapName), nil)
	if err != nil {
		s.Errorf("Unable to load map at %s : %w", filepath.Join(stateDir, mapName), err)
	} else {
		err = m.Put(k, v)
		if err != nil {
			s.Errorf("Map update for %s failed : %w", mapName, err)
		} else {
			s.Infof("Map update for %s succeeded", mapName)
		}
	}

	err = server.Serve(ln)
	if err != nil {
		s.Fatalf("Unable to start HTTP server %w", err)
	}
}
