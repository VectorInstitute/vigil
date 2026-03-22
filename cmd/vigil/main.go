package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/VectorInstitute/vigil/internal/audit"
	"github.com/VectorInstitute/vigil/internal/detector"
	"github.com/VectorInstitute/vigil/internal/loader"
	"github.com/VectorInstitute/vigil/internal/profiles"
	"github.com/VectorInstitute/vigil/internal/ui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vigil",
	Short: "eBPF-based runtime security for AI inference workloads",
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Attach to AI inference processes and enforce the behavioral profile",
	RunE:  runWatch,
}

var watchFlags struct {
	framework string
	profile   string
	bpfObj    string
	uiEnabled bool
	uiPort    int
}

func init() {
	watchCmd.Flags().StringVar(&watchFlags.framework, "framework", "ollama", "AI framework profile to use (ollama, vllm, llamacpp)")
	watchCmd.Flags().StringVar(&watchFlags.profile, "profile", "", "Path to a custom profile YAML (overrides --framework)")
	watchCmd.Flags().StringVar(&watchFlags.bpfObj, "bpf-obj", "/usr/lib/vigil/vigil.bpf.o", "Path to compiled eBPF object file")
	watchCmd.Flags().BoolVar(&watchFlags.uiEnabled, "ui", false, "Start the real-time web UI")
	watchCmd.Flags().IntVar(&watchFlags.uiPort, "port", 7394, "Port to serve the web UI on (requires --ui)")
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(profileCmd)
}

func runWatch(cmd *cobra.Command, _ []string) error {
	profilePath := watchFlags.profile
	if profilePath == "" {
		profilePath = fmt.Sprintf("profiles/%s.yaml", watchFlags.framework)
	}

	p, err := profiles.LoadFile(profilePath)
	if err != nil {
		return fmt.Errorf("loading profile: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "vigil: loaded profile %q\n", p.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "vigil: attaching eBPF programs (requires root + Linux)...\n")

	l, err := loader.Load(p, watchFlags.bpfObj)
	if err != nil {
		return fmt.Errorf("loading eBPF: %w\nEnsure: Linux kernel 5.7+, CONFIG_BPF_LSM=y, lsm=bpf, run as root", err)
	}
	defer l.Close()

	det := detector.New(p)
	log := audit.New(cmd.OutOrStdout())

	var uiServer *ui.Server
	if watchFlags.uiEnabled {
		uiServer = ui.New(p.Name)
		go func() {
			addr := fmt.Sprintf(":%d", watchFlags.uiPort)
			fmt.Fprintf(cmd.OutOrStdout(), "vigil: UI available at http://localhost%s\n", addr)
			if err := http.ListenAndServe(addr, uiServer.Handler()); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "vigil: UI server error: %v\n", err)
			}
		}()
	}

	fmt.Fprintf(cmd.OutOrStdout(), "vigil: watching — press Ctrl+C to stop\n")

	for {
		e, err := l.ReadEvent()
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}
		dec := det.Evaluate(e)
		if dec.Action == detector.Skip {
			continue
		}
		if dec.Action == detector.Block {
			_ = l.BlockIP(e.DestIP) // add to kernel block map for future connections
		}
		log.Log(dec)
		if uiServer != nil {
			uiServer.Broadcast(dec)
		}
	}
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage behavioral profiles",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available built-in profiles",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), "Built-in profiles:")
		fmt.Fprintln(cmd.OutOrStdout(), "  ollama    — Ollama LLM server")
		fmt.Fprintln(cmd.OutOrStdout(), "  vllm      — vLLM inference server (coming soon)")
		fmt.Fprintln(cmd.OutOrStdout(), "  llamacpp  — llama.cpp server (coming soon)")
	},
}

func init() {
	profileCmd.AddCommand(profileListCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
