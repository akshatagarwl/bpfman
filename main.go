package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

//go:generate clang -Wall -O2 -g -target bpf -DUSE_PERF_BUF -c bpf/probe.bpf.c -Ibpf/include/ -o bpf/bin/probe_perf.bpf.o
//go:generate clang -Wall -O2 -g -target bpf -DUSE_RING_BUF -c bpf/probe.bpf.c -Ibpf/include/ -o bpf/bin/probe_ring.bpf.o

//go:embed bpf/bin/probe_perf.bpf.o
var ProbePerf []byte

//go:embed bpf/bin/probe_ring.bpf.o
var ProbeRing []byte

func RingEventHandler(_ int, _ []byte, _ *manager.RingBuffer, _ *manager.Manager) {
	fmt.Println("data received from ring")
}

func PerfEventHandler(_ int, _ []byte, _ *manager.PerfMap, _ *manager.Manager) {
	fmt.Println("data received from perf")
}

func main() {
	if err := run(); err != nil {
		slog.Error("unable to run", "error", err)
	}
}

func HaveRingBuffers() bool {
	return features.HaveMapType(ebpf.RingBuf) == nil
}

func run() error {
	var m *manager.Manager

	if HaveRingBuffers() {
		m = &manager.Manager{
			Probes: []*manager.Probe{
				{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "sys_enter_sendto",
					},
				},
			},
			RingBuffers: []*manager.RingBuffer{
				{
					Map: manager.Map{
						Name: "events",
					},
					RingBufferOptions: manager.RingBufferOptions{
						DataHandler: RingEventHandler,
					},
				},
			},
		}

		if err := m.Init(bytes.NewReader(ProbeRing)); err != nil {
			slog.Error("unable to init manager", "error", err)
			return err
		}

		defer func() {
			if err := m.Stop(manager.CleanAll); err != nil {
				slog.Error("unable to stop manager", "error", err)
			}
		}()
	} else {
		m = &manager.Manager{
			Probes: []*manager.Probe{
				{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EBPFFuncName: "sys_enter_sendto",
					},
				},
			},
			PerfMaps: []*manager.PerfMap{
				{
					Map: manager.Map{
						Name: "perf_events",
					},
					PerfMapOptions: manager.PerfMapOptions{
						DataHandler: PerfEventHandler,
					},
				},
			},
		}

		if err := m.Init(bytes.NewReader(ProbePerf)); err != nil {
			slog.Error("unable to init manager", "error", err)
			return err
		}

		defer func() {
			if err := m.Stop(manager.CleanAll); err != nil {
				slog.Error("unable to stop manager", "error", err)
			}
		}()
	}

	slog.Info("manager declared", "manager", m)

	if err := m.Start(); err != nil {
		slog.Error("unable to start", "error", err)
		return err
	}

	slog.Info("successfully started, run (sudo bpftool prog tracelog)")

	select {}

	return nil
}
