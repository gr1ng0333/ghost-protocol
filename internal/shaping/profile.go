package shaping

import "fmt"

// Profile defines a traffic shaping profile that describes the statistical
// distribution of frame sizes and timing for traffic mimicry.
type Profile struct {
	Name       string       `json:"name"`
	SizeDist   Distribution `json:"size_distribution"`
	TimingDist Distribution `json:"timing_distribution"`
	BurstConf  BurstConfig  `json:"burst_config"`
}

// Distribution describes a statistical distribution used for sampling
// frame sizes or timing values.
type Distribution struct {
	Type    string    `json:"type"` // "pareto", "lognormal", "uniform", "empirical"
	Params  []float64 `json:"params"`
	Samples []float64 `json:"samples,omitempty"` // for empirical distributions
}

// BurstConfig controls traffic burst characteristics for realistic shaping.
type BurstConfig struct {
	MinBurstBytes  int          `json:"min_burst_bytes"`
	MaxBurstBytes  int          `json:"max_burst_bytes"`
	MinPauseMs     int          `json:"min_pause_ms"`
	MaxPauseMs     int          `json:"max_pause_ms"`
	BurstCountDist Distribution `json:"burst_count_distribution"`
}

// knownDistTypes lists the supported distribution types.
var knownDistTypes = map[string]bool{
	"pareto":    true,
	"lognormal": true,
	"uniform":   true,
	"empirical": true,
}

// Validate checks that all Profile fields are well-formed.
func (p *Profile) Validate() error {
	if err := validateDist("size_distribution", &p.SizeDist); err != nil {
		return err
	}
	if err := validateDist("timing_distribution", &p.TimingDist); err != nil {
		return err
	}
	if p.BurstConf.MinBurstBytes > p.BurstConf.MaxBurstBytes && p.BurstConf.MaxBurstBytes > 0 {
		return fmt.Errorf("profile: burst_config.min_burst_bytes (%d) > max_burst_bytes (%d)",
			p.BurstConf.MinBurstBytes, p.BurstConf.MaxBurstBytes)
	}
	if p.BurstConf.MinPauseMs > p.BurstConf.MaxPauseMs && p.BurstConf.MaxPauseMs > 0 {
		return fmt.Errorf("profile: burst_config.min_pause_ms (%d) > max_pause_ms (%d)",
			p.BurstConf.MinPauseMs, p.BurstConf.MaxPauseMs)
	}
	return nil
}

func validateDist(name string, d *Distribution) error {
	if !knownDistTypes[d.Type] {
		return fmt.Errorf("profile: %s.type %q is not supported", name, d.Type)
	}
	if d.Type == "empirical" {
		if len(d.Samples) == 0 {
			return fmt.Errorf("profile: %s: empirical distribution requires non-empty samples", name)
		}
	} else {
		if len(d.Params) == 0 {
			return fmt.Errorf("profile: %s: distribution %q requires non-empty params", name, d.Type)
		}
	}
	return nil
}
