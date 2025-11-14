// internal/config/loader.go
package config

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Load orquesta la carga de configuración desde todas las fuentes (defaults, ficheros, flags)
// y devuelve una única struct ResolvedConfig con los valores finales.
func Load(cmd *cobra.Command) (*ResolvedConfig, error) {
	// 1. Empezamos con los valores por defecto definidos en los flags de Cobra.
	cfg := loadDefaultsFromFlags(cmd)

	// 2. Aplicamos el fichero de configuración base (config.yaml).
	err := applyBaseConfig(cmd, cfg)
	if err != nil {
		return nil, err
	}

	// 3. Aplicamos el perfil táctico (profiles.yaml), si se especifica.
	err = applyProfileConfig(cmd, cfg)
	if err != nil {
		return nil, err
	}

	// 4. Finalmente, leemos los valores de los flags de nuevo.
	// Como los flags tienen la máxima prioridad, esto sobreescribirá cualquier
	// valor que viniera de los ficheros de configuración.
	loadFinalValuesFromFlags(cmd, cfg)

	return cfg, nil
}

// loadDefaultsFromFlags inicializa ResolvedConfig con los valores por defecto de los flags.
func loadDefaultsFromFlags(cmd *cobra.Command) *ResolvedConfig {
	// Esta función es necesaria para que tengamos una base sobre la que trabajar,
	// incluso si no hay ficheros de configuración. Cobra no expone los valores
	// por defecto directamente, así que los leemos como si fueran valores actuales.
	cfg := &ResolvedConfig{}
	loadFinalValuesFromFlags(cmd, cfg)
	return cfg
}

// applyBaseConfig encuentra y aplica los valores de config.yaml.
func applyBaseConfig(cmd *cobra.Command, cfg *ResolvedConfig) error {
	configPath, err := findConfigFile(cfg.ConfigFilePath)
	if err != nil {
		log.Printf("Advertencia: no se pudo buscar el fichero de configuración: %v", err)
		return nil // No es un error fatal.
	}
	if configPath == "" {
		if cmd.Flags().Changed("config") {
			return fmt.Errorf("el fichero de configuración especificado %s no se encontró", cfg.ConfigFilePath)
		}
		return nil // No se encontró fichero, continuamos.
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("error leyendo el fichero de configuración %s: %w", configPath, err)
	}
	var baseCfg AppConfig
	if err := yaml.Unmarshal(data, &baseCfg); err != nil {
		return fmt.Errorf("error parseando el fichero de configuración YAML %s: %w", configPath, err)
	}

	applyAppConfig(cmd, cfg, &baseCfg)
	return nil
}

// applyProfileConfig encuentra y aplica el perfil seleccionado de profiles.yaml.
func applyProfileConfig(cmd *cobra.Command, cfg *ResolvedConfig) error {
	if cfg.ProfileName == "" {
		return nil // No se ha solicitado ningún perfil.
	}

	profilesPath, err := findProfilesFile(cfg.ProfilesFilePath, cfg.ConfigFilePath)
	if err != nil || profilesPath == "" {
		return fmt.Errorf("--profile '%s' especificado pero no se pudo encontrar el fichero profiles.yaml: %w", cfg.ProfileName, err)
	}

	data, err := os.ReadFile(profilesPath)
	if err != nil {
		return fmt.Errorf("error leyendo el fichero de perfiles %s: %w", profilesPath, err)
	}
	var profilesFile ProfilesFile
	if err := yaml.Unmarshal(data, &profilesFile); err != nil {
		return fmt.Errorf("error parseando el fichero de perfiles YAML %s: %w", profilesPath, err)
	}

	profile, found := profilesFile.Profiles[cfg.ProfileName]
	if !found {
		return fmt.Errorf("perfil '%s' no encontrado en %s", cfg.ProfileName, profilesPath)
	}

	if cfg.VerboseCount > 0 {
		log.Printf("Aplicando perfil '%s': %s", cfg.ProfileName, profile.Description)
	}
	applyProfile(cmd, cfg, &profile)
	return nil
}

// findConfigFile busca el fichero de configuración con una precedencia clara.
func findConfigFile(explicitPath string) (string, error) {
	if explicitPath != "" {
		return explicitPath, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("no se pudo obtener el directorio del usuario actual: %w", err)
	}
	userConfigPath := filepath.Join(usr.HomeDir, ".config", "go-arpscan", "config.yaml")
	if _, err := os.Stat(userConfigPath); err == nil {
		return userConfigPath, nil
	}
	return "", nil
}

// findProfilesFile busca el fichero de perfiles con una precedencia clara.
func findProfilesFile(explicitProfilesPath, explicitConfigPath string) (string, error) {
	// 1. Flag explícito --profiles
	if explicitProfilesPath != "" {
		if _, err := os.Stat(explicitProfilesPath); err == nil {
			return explicitProfilesPath, nil
		}
		return "", fmt.Errorf("el fichero de perfiles especificado '%s' no existe", explicitProfilesPath)
	}

	// 2. Directorio de trabajo actual
	localPath := "profiles.yaml"
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 3. Junto al fichero de configuración (si se usó --config)
	if explicitConfigPath != "" {
		dir := filepath.Dir(explicitConfigPath)
		path := filepath.Join(dir, "profiles.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// 4. Directorio de configuración del usuario por defecto
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("no se pudo obtener el directorio del usuario actual: %w", err)
	}
	userProfilesPath := filepath.Join(usr.HomeDir, ".config", "go-arpscan", "profiles.yaml")
	if _, err := os.Stat(userProfilesPath); err == nil {
		return userProfilesPath, nil
	}

	return "", nil // No se encontró ningún fichero
}

// applyAppConfig aplica valores desde AppConfig (config.yaml) a ResolvedConfig.
func applyAppConfig(cmd *cobra.Command, cfg *ResolvedConfig, baseCfg *AppConfig) {
	if !cmd.Flags().Changed("interface") && baseCfg.Interface != "" {
		cfg.IfaceName = baseCfg.Interface
	}
	if !cmd.Flags().Changed("verbose") && baseCfg.Verbose > 0 {
		cfg.VerboseCount = baseCfg.Verbose
	}
	if !cmd.Flags().Changed("color") && baseCfg.UI.Color != "" {
		cfg.ColorMode = baseCfg.UI.Color
	}
	if !cmd.Flags().Changed("progress") && baseCfg.UI.Progress {
		cfg.ShowProgress = true
	}
	if !cmd.Flags().Changed("host-timeout") && baseCfg.Scan.HostTimeout > 0 {
		cfg.HostTimeout = baseCfg.Scan.HostTimeout
	}
	if !cmd.Flags().Changed("scan-timeout") && baseCfg.Scan.ScanTimeout > 0 {
		cfg.ScanTimeout = baseCfg.Scan.ScanTimeout
	}
	if !cmd.Flags().Changed("retry") && baseCfg.Scan.Retry > 0 {
		cfg.Retry = baseCfg.Scan.Retry
	}
	if !cmd.Flags().Changed("bandwidth") && !cmd.Flags().Changed("interval") && baseCfg.Scan.Bandwidth != "" {
		cfg.Bandwidth = baseCfg.Scan.Bandwidth
	}
	if !cmd.Flags().Changed("interval") && !cmd.Flags().Changed("bandwidth") && baseCfg.Scan.Interval > 0 {
		cfg.Interval = baseCfg.Scan.Interval
	}
	if !cmd.Flags().Changed("backoff") && baseCfg.Scan.BackoffFactor > 0 {
		cfg.BackoffFactor = baseCfg.Scan.BackoffFactor
	}
	if !cmd.Flags().Changed("random") && baseCfg.Scan.Random {
		cfg.Random = true
	}
	if !cmd.Flags().Changed("monitor") && baseCfg.Monitor.Enabled {
		cfg.MonitorMode = true
	}
	if !cmd.Flags().Changed("monitor-interval") && baseCfg.Monitor.Interval > 0 {
		cfg.MonitorInterval = baseCfg.Monitor.Interval
	}
	if !cmd.Flags().Changed("monitor-removal-threshold") && baseCfg.Monitor.RemovalThreshold > 0 {
		cfg.MonitorRemovalThreshold = baseCfg.Monitor.RemovalThreshold
	}
	// <<< INICIO DE LECTURA DE CONFIG DE SPOOFING DESDE YAML >>>
	if !cmd.Flags().Changed("detect-arp-spoofing") && baseCfg.Monitor.DetectArpSpoofing {
		cfg.DetectArpSpoofing = true
	}
	if !cmd.Flags().Changed("monitor-gateway") && baseCfg.Monitor.Gateway != "" {
		cfg.MonitorGatewayIP = baseCfg.Monitor.Gateway
	}
	// <<< FIN DE LECTURA DE CONFIG DE SPOOFING DESDE YAML >>>
	if !cmd.Flags().Changed("webhook-url") && baseCfg.Monitor.WebhookURL != "" {
		cfg.WebhookURL = baseCfg.Monitor.WebhookURL
	}
	if !cmd.Flags().Changed("webhook-header") && len(baseCfg.Monitor.WebhookHeaders) > 0 {
		cfg.WebhookHeaders = baseCfg.Monitor.WebhookHeaders
	}
	if !cmd.Flags().Changed("spoof-interval") && baseCfg.Spoofing.Interval > 0 {
		cfg.SpoofInterval = baseCfg.Spoofing.Interval
	}
	if !cmd.Flags().Changed("spoof-mac-timeout") && baseCfg.Spoofing.MACTimeout > 0 {
		cfg.MACRequestTimeout = baseCfg.Spoofing.MACTimeout
	}
	if !cmd.Flags().Changed("spoof-restore-duration") && baseCfg.Spoofing.RestoreDuration > 0 {
		cfg.RestoreDuration = baseCfg.Spoofing.RestoreDuration
	}
	if !cmd.Flags().Changed("spoof-restore-interval") && baseCfg.Spoofing.RestoreInterval > 0 {
		cfg.RestoreInterval = baseCfg.Spoofing.RestoreInterval
	}
	if !cmd.Flags().Changed("rtt") && baseCfg.Output.RTT {
		cfg.ShowRTT = true
	}
	if !cmd.Flags().Changed("numeric") && baseCfg.Output.Numeric {
		cfg.Numeric = true
	}
	formatFlagsSet := cmd.Flags().Changed("json") || cmd.Flags().Changed("csv") || cmd.Flags().Changed("plain") || cmd.Flags().Changed("quiet")
	if !formatFlagsSet && baseCfg.Output.Format != "" {
		switch strings.ToLower(baseCfg.Output.Format) {
		case "json":
			cfg.JSONOutput = true
		case "csv":
			cfg.CSVOutput = true
		case "plain":
			cfg.Plain = true
		case "quiet":
			cfg.Quiet = true
		}
	}
	if !cmd.Flags().Changed("ouifile") && baseCfg.Files.OUIFile != "" {
		cfg.OUIFilePath = baseCfg.Files.OUIFile
	}
	if !cmd.Flags().Changed("iabfile") && baseCfg.Files.IABFile != "" {
		cfg.IABFilePath = baseCfg.Files.IABFile
	}
	if !cmd.Flags().Changed("macfile") && baseCfg.Files.MACFile != "" {
		cfg.MACFilePath = baseCfg.Files.MACFile
	}
	if !cmd.Flags().Changed("vlan") && baseCfg.Advanced.Vlan > 0 {
		cfg.VlanID = baseCfg.Advanced.Vlan
	}
	if !cmd.Flags().Changed("arpspa") && baseCfg.Advanced.ArpSPA != "" {
		cfg.ArpSPA = baseCfg.Advanced.ArpSPA
	}
	if !cmd.Flags().Changed("arpsha") && baseCfg.Advanced.ArpSHA != "" {
		cfg.ArpSHA = baseCfg.Advanced.ArpSHA
	}
	if !cmd.Flags().Changed("srcaddr") && baseCfg.Advanced.EthSrcMAC != "" {
		cfg.EthSrcMAC = baseCfg.Advanced.EthSrcMAC
	}
	if !cmd.Flags().Changed("destaddr") && baseCfg.Advanced.EthDstMAC != "" {
		cfg.EthDstMAC = baseCfg.Advanced.EthDstMAC
	}
	if !cmd.Flags().Changed("arptha") && baseCfg.Advanced.ArpTHA != "" {
		cfg.ArpTHA = baseCfg.Advanced.ArpTHA
	}
	if !cmd.Flags().Changed("arpop") && baseCfg.Advanced.ArpOpCode > 0 {
		cfg.ArpOpCode = baseCfg.Advanced.ArpOpCode
	}
	if !cmd.Flags().Changed("prototype") && baseCfg.Advanced.Prototype != "" {
		cfg.EthPrototype = baseCfg.Advanced.Prototype
	}
	if !cmd.Flags().Changed("arphrd") && baseCfg.Advanced.ArpHrd > 0 {
		cfg.ArpHrd = baseCfg.Advanced.ArpHrd
	}
	if !cmd.Flags().Changed("arppro") && baseCfg.Advanced.ArpPro != "" {
		cfg.ArpPro = baseCfg.Advanced.ArpPro
	}
	if !cmd.Flags().Changed("arphln") && baseCfg.Advanced.ArpHln > 0 {
		cfg.ArpHln = baseCfg.Advanced.ArpHln
	}
	if !cmd.Flags().Changed("arppln") && baseCfg.Advanced.ArpPln > 0 {
		cfg.ArpPln = baseCfg.Advanced.ArpPln
	}
	if !cmd.Flags().Changed("padding") && baseCfg.Advanced.Padding != "" {
		cfg.PaddingHex = baseCfg.Advanced.Padding
	}
	if !cmd.Flags().Changed("llc") && baseCfg.Advanced.LLC {
		cfg.UseLLC = true
	}
	if !cmd.Flags().Changed("ignoredups") && baseCfg.Advanced.IgnoreDups {
		cfg.IgnoreDups = true
	}
}

// applyProfile aplica valores desde ProfileConfig (profiles.yaml) a ResolvedConfig.
func applyProfile(cmd *cobra.Command, cfg *ResolvedConfig, profile *ProfileConfig) {
	randomizedMACs := make(map[string]string)

	randomizeAndSet := func(template string) (string, error) {
		if val, ok := randomizedMACs[template]; ok {
			return val, nil
		}
		resolved, err := randomizeMAC(template)
		if err != nil {
			return "", err
		}
		randomizedMACs[template] = resolved
		return resolved, nil
	}

	if !cmd.Flags().Changed("arpsha") && profile.ArpSHA != "" {
		resolvedMAC, err := randomizeAndSet(profile.ArpSHA)
		if err != nil {
			log.Fatalf("Error al aleatorizar arpsha en el perfil '%s': %v", cfg.ProfileName, err)
		}
		cfg.ArpSHA = resolvedMAC
	}
	if !cmd.Flags().Changed("srcaddr") && profile.EthSrcMAC != "" {
		resolvedMAC, err := randomizeAndSet(profile.EthSrcMAC)
		if err != nil {
			log.Fatalf("Error al aleatorizar srcaddr en el perfil '%s': %v", cfg.ProfileName, err)
		}
		cfg.EthSrcMAC = resolvedMAC
	}
	if !cmd.Flags().Changed("host-timeout") && profile.HostTimeout > 0 {
		cfg.HostTimeout = profile.HostTimeout
	}
	if !cmd.Flags().Changed("retry") && profile.Retry > 0 {
		cfg.Retry = profile.Retry
	}
	if !cmd.Flags().Changed("backoff") && profile.BackoffFactor > 0 {
		cfg.BackoffFactor = profile.BackoffFactor
	}
	if !cmd.Flags().Changed("bandwidth") && !cmd.Flags().Changed("interval") && profile.Bandwidth != "" {
		cfg.Bandwidth = profile.Bandwidth
	}
	if !cmd.Flags().Changed("llc") && profile.LLC {
		cfg.UseLLC = true
	}
	if !cmd.Flags().Changed("random") && profile.Random {
		cfg.Random = true
	}
	if !cmd.Flags().Changed("arpop") && profile.ArpOpCode > 0 {
		cfg.ArpOpCode = profile.ArpOpCode
	}
	if !cmd.Flags().Changed("padding") && profile.Padding != "" {
		cfg.PaddingHex = profile.Padding
	}
}

// randomizeMAC toma una plantilla de MAC (e.g., "00:11:22:XX:XX:XX")
// y reemplaza cada "XX" con un octeto hexadecimal aleatorio.
func randomizeMAC(template string) (string, error) {
	if !strings.Contains(strings.ToUpper(template), "XX") {
		return template, nil
	}
	parts := strings.Split(template, ":")
	if len(parts) != 6 {
		return "", fmt.Errorf("plantilla de MAC para aleatorizar inválida: '%s'", template)
	}
	var resultParts []string
	for _, part := range parts {
		if strings.ToUpper(part) == "XX" {
			b := byte(rand.Intn(256))
			resultParts = append(resultParts, fmt.Sprintf("%02X", b))
		} else {
			resultParts = append(resultParts, part)
		}
	}
	return strings.Join(resultParts, ":"), nil
}

// loadFinalValuesFromFlags lee los valores de los flags tal como están y los
// guarda en la struct ResolvedConfig.
func loadFinalValuesFromFlags(cmd *cobra.Command, cfg *ResolvedConfig) {
	// Esta función es la que realmente lee los valores de los flags.
	// Se llama al principio para obtener los defaults, y al final para
	// sobreescribir con los valores explícitos del usuario.
	cfg.ConfigFilePath, _ = cmd.Flags().GetString("config")
	cfg.ProfilesFilePath, _ = cmd.Flags().GetString("profiles")
	cfg.ProfileName, _ = cmd.Flags().GetString("profile")
	cfg.IfaceName, _ = cmd.Flags().GetString("interface")
	cfg.ScanTimeout, _ = cmd.Flags().GetDuration("scan-timeout")
	cfg.UseLocalnet, _ = cmd.Flags().GetBool("localnet")
	cfg.FilePath, _ = cmd.Flags().GetString("file")
	cfg.ExcludeTargets, _ = cmd.Flags().GetStringSlice("exclude")
	cfg.ExcludeFilePath, _ = cmd.Flags().GetString("exclude-file")
	cfg.Numeric, _ = cmd.Flags().GetBool("numeric")
	cfg.HostTimeout, _ = cmd.Flags().GetDuration("host-timeout")
	cfg.Retry, _ = cmd.Flags().GetInt("retry")
	cfg.Interval, _ = cmd.Flags().GetDuration("interval")
	cfg.Bandwidth, _ = cmd.Flags().GetString("bandwidth")
	cfg.BackoffFactor, _ = cmd.Flags().GetFloat64("backoff")
	cfg.SpoofTargetIP, _ = cmd.Flags().GetString("spoof")
	cfg.GatewayIP, _ = cmd.Flags().GetString("gateway")
	cfg.DetectPromiscTargetIP, _ = cmd.Flags().GetString("detect-promisc")
	cfg.SpoofInterval, _ = cmd.Flags().GetDuration("spoof-interval")
	cfg.MACRequestTimeout, _ = cmd.Flags().GetDuration("spoof-mac-timeout")
	cfg.RestoreDuration, _ = cmd.Flags().GetDuration("spoof-restore-duration")
	cfg.RestoreInterval, _ = cmd.Flags().GetDuration("spoof-restore-interval")
	cfg.MonitorMode, _ = cmd.Flags().GetBool("monitor")
	cfg.MonitorInterval, _ = cmd.Flags().GetDuration("monitor-interval")
	cfg.MonitorRemovalThreshold, _ = cmd.Flags().GetDuration("monitor-removal-threshold")
	// <<< INICIO DE LECTURA DE FLAGS DE SPOOFING DESDE LA CLI >>>
	cfg.DetectArpSpoofing, _ = cmd.Flags().GetBool("detect-arp-spoofing")
	cfg.MonitorGatewayIP, _ = cmd.Flags().GetString("monitor-gateway")
	// <<< FIN DE LECTURA DE FLAGS DE SPOOFING DESDE LA CLI >>>
	cfg.WebhookURL, _ = cmd.Flags().GetString("webhook-url")
	cfg.WebhookHeaders, _ = cmd.Flags().GetStringSlice("webhook-header")
	cfg.ArpSPA, _ = cmd.Flags().GetString("arpspa")
	cfg.ArpSHA, _ = cmd.Flags().GetString("arpsha")
	cfg.EthSrcMAC, _ = cmd.Flags().GetString("srcaddr")
	cfg.ArpOpCode, _ = cmd.Flags().GetInt("arpop")
	cfg.EthDstMAC, _ = cmd.Flags().GetString("destaddr")
	cfg.ArpTHA, _ = cmd.Flags().GetString("arptha")
	cfg.EthPrototype, _ = cmd.Flags().GetString("prototype")
	cfg.ArpHrd, _ = cmd.Flags().GetInt("arphrd")
	cfg.ArpPro, _ = cmd.Flags().GetString("arppro")
	cfg.ArpHln, _ = cmd.Flags().GetInt("arphln")
	cfg.ArpPln, _ = cmd.Flags().GetInt("arppln")
	cfg.PaddingHex, _ = cmd.Flags().GetString("padding")
	cfg.UseLLC, _ = cmd.Flags().GetBool("llc")
	cfg.OUIFilePath, _ = cmd.Flags().GetString("ouifile")
	cfg.IABFilePath, _ = cmd.Flags().GetString("iabfile")
	cfg.MACFilePath, _ = cmd.Flags().GetString("macfile")
	cfg.Quiet, _ = cmd.Flags().GetBool("quiet")
	cfg.Plain, _ = cmd.Flags().GetBool("plain")
	cfg.JSONOutput, _ = cmd.Flags().GetBool("json")
	cfg.CSVOutput, _ = cmd.Flags().GetBool("csv")
	cfg.StateFilePath, _ = cmd.Flags().GetString("state-file")
	cfg.DiffMode, _ = cmd.Flags().GetBool("diff")
	cfg.ShowProgress, _ = cmd.Flags().GetBool("progress")
	cfg.ShowRTT, _ = cmd.Flags().GetBool("rtt")
	cfg.PcapSaveFile, _ = cmd.Flags().GetString("pcapsavefile")
	cfg.IgnoreDups, _ = cmd.Flags().GetBool("ignoredups")
	cfg.ColorMode, _ = cmd.Flags().GetString("color")
	cfg.Random, _ = cmd.Flags().GetBool("random")
	cfg.RandomSeed, _ = cmd.Flags().GetInt64("randomseed")
	cfg.VlanID, _ = cmd.Flags().GetInt("vlan")
	cfg.Snaplen, _ = cmd.Flags().GetInt("snap")
	cfg.VerboseCount, _ = cmd.Flags().GetCount("verbose")
}
