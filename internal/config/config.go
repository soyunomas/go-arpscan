// internal/config/config.go
package config

import (
	"time"
)

// AppConfig es la estructura raíz que mapea el fichero de configuración YAML principal (config.yaml).
type AppConfig struct {
	Interface string         `yaml:"interface"`
	Verbose   int            `yaml:"verbose"`
	UI        UIConfig       `yaml:"ui"`
	Scan      ScanConfig     `yaml:"scan"`
	Monitor   MonitorConfig  `yaml:"monitor"`
	Output    OutputConfig   `yaml:"output"`
	Spoofing  SpoofingConfig `yaml:"spoofing"`
	Advanced  AdvancedConfig `yaml:"advanced"`
	Files     FilePaths      `yaml:"files"`
}

type UIConfig struct {
	Color    string `yaml:"color"`
	Progress bool   `yaml:"progress"`
}

type ScanConfig struct {
	HostTimeout   time.Duration `yaml:"host-timeout"`
	ScanTimeout   time.Duration `yaml:"scan-timeout"`
	Retry         int           `yaml:"retry"`
	Bandwidth     string        `yaml:"bandwidth"`
	Interval      time.Duration `yaml:"interval"`
	BackoffFactor float64       `yaml:"backoff"`
	Random        bool          `yaml:"random"`
}

type MonitorConfig struct {
	Enabled             bool          `yaml:"enabled"`
	Interval            time.Duration `yaml:"interval"`
	RemovalThreshold    time.Duration `yaml:"removal-threshold"`
	DetectArpSpoofing   bool          `yaml:"detect-arp-spoofing"` // <<< NUEVO CAMPO
	Gateway             string        `yaml:"gateway"`             // <<< NUEVO CAMPO
	WebhookURL          string        `yaml:"webhook-url"`
	WebhookHeaders      []string      `yaml:"webhook-headers"`
}

type OutputConfig struct {
	Format  string `yaml:"format"`
	RTT     bool   `yaml:"rtt"`
	Numeric bool   `yaml:"numeric"`
}

type SpoofingConfig struct {
	Interval        time.Duration `yaml:"interval"`
	MACTimeout      time.Duration `yaml:"mac-timeout"`
	RestoreDuration time.Duration `yaml:"restore-duration"`
	RestoreInterval time.Duration `yaml:"restore-interval"`
}

type AdvancedConfig struct {
	Vlan       int    `yaml:"vlan"`
	ArpSPA     string `yaml:"arpspa"`
	ArpSHA     string `yaml:"arpsha"`
	EthSrcMAC  string `yaml:"srcaddr"`
	EthDstMAC  string `yaml:"destaddr"`
	ArpTHA     string `yaml:"arptha"`
	ArpOpCode  int    `yaml:"arpop"`
	Prototype  string `yaml:"prototype"`
	ArpHrd     int    `yaml:"arphrd"`
	ArpPro     string `yaml:"arppro"`
	ArpHln     int    `yaml:"arphln"`
	ArpPln     int    `yaml:"arppln"`
	Padding    string `yaml:"padding"`
	LLC        bool   `yaml:"llc"`
	IgnoreDups bool   `yaml:"ignoredups"`
}

type FilePaths struct {
	OUIFile string `yaml:"ouifile"`
	IABFile string `yaml:"iabfile"`
	MACFile string `yaml:"macfile"`
}

// ProfilesFile es la estructura raíz para el fichero de perfiles (profiles.yaml).
type ProfilesFile struct {
	Profiles map[string]ProfileConfig `yaml:"profiles"`
}

// ProfileConfig contiene los parámetros para un único perfil táctico.
type ProfileConfig struct {
	Description   string        `yaml:"description"`
	ArpSHA        string        `yaml:"arpsha"`
	EthSrcMAC     string        `yaml:"srcaddr"`
	HostTimeout   time.Duration `yaml:"host-timeout"`
	Retry         int           `yaml:"retry"`
	BackoffFactor float64       `yaml:"backoff"`
	Bandwidth     string        `yaml:"bandwidth"`
	LLC           bool          `yaml:"llc"`
	Random        bool          `yaml:"random"`
	ArpOpCode     int           `yaml:"arpop"`
	Padding       string        `yaml:"padding"`
}

// ResolvedConfig contiene todos los parámetros de configuración finales
// después de aplicar la cascada de prioridades (flags > perfil > config.yaml > defaults).
// Esta es la "única fuente de verdad" para el resto de la aplicación.
type ResolvedConfig struct {
	// Paths
	ConfigFilePath   string
	ProfilesFilePath string
	ProfileName      string
	FilePath         string
	OUIFilePath      string
	IABFilePath      string
	MACFilePath      string
	PcapSaveFile     string
	StateFilePath    string
	ExcludeFilePath  string

	// Interface & Targets
	IfaceName      string
	UseLocalnet    bool
	Numeric        bool
	ExcludeTargets []string

	// Scan Timing & Control
	ScanTimeout   time.Duration
	HostTimeout   time.Duration
	Retry         int
	Interval      time.Duration
	Bandwidth     string
	BackoffFactor float64
	Random        bool
	RandomSeed    int64

	// Spoofing
	SpoofTargetIP         string
	GatewayIP             string
	DetectPromiscTargetIP string
	SpoofInterval         time.Duration
	MACRequestTimeout     time.Duration
	RestoreDuration       time.Duration
	RestoreInterval       time.Duration

	// Monitoring
	MonitorMode             bool
	MonitorInterval         time.Duration
	MonitorRemovalThreshold time.Duration
	DetectArpSpoofing       bool   // <<< NUEVO CAMPO
	MonitorGatewayIP        string // <<< NUEVO CAMPO
	WebhookURL              string
	WebhookHeaders          []string

	// Packet Manipulation
	ArpSPA       string
	ArpSHA       string
	EthSrcMAC    string
	ArpOpCode    int
	EthDstMAC    string
	ArpTHA       string
	EthPrototype string
	ArpHrd       int
	ArpPro       string
	ArpHln       int
	ArpPln       int
	PaddingHex   string
	UseLLC       bool
	VlanID       int
	Snaplen      int

	// Output & UI
	Quiet        bool
	Plain        bool
	JSONOutput   bool
	CSVOutput    bool
	DiffMode     bool
	ShowProgress bool
	ShowRTT      bool
	IgnoreDups   bool
	ColorMode    string
	VerboseCount int
}
