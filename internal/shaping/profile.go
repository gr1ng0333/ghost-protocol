package shaping

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
