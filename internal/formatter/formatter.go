// internal/formatter/formatter.go
package formatter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"go-arpscan/internal/scanner"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// JSONResult y JSONOutput se mantienen exportadas para runner.
type JSONResult struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	RTTms  int64  `json:"rtt_ms"`
	Vendor string `json:"vendor"`
	Status string `json:"status,omitempty"`
}

type JSONOutput struct {
	Results []JSONResult `json:"results"`
	Summary struct {
		Conflicts []string `json:"conflicts,omitempty"`
		MultiIP   []string `json:"multi_ip,omitempty"`
	} `json:"summary"`
}

const (
	ipColWidth     = 15
	macColWidth    = 17
	rttColWidth    = 12
	statusColWidth = 12
	colPadding     = "    "
)

var (
	ipColor     = color.New(color.FgHiGreen).SprintFunc()
	macColor    = color.New(color.FgHiYellow).SprintFunc()
	vendorColor = color.New(color.FgHiCyan).SprintFunc()
	rttColor    = color.New(color.FgHiMagenta).SprintFunc()
	statusColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	warnColor = color.New(color.FgHiRed).SprintFunc()
	infoColor = color.New(color.FgHiBlue).SprintFunc()
	headerColor = color.New(color.FgHiWhite, color.Bold).SprintFunc()
)

type Formatter interface {
	PrintHeader()
	PrintResult(result scanner.ScanResult)
	PrintFooter(conflictSummaries []string, multiIPSummaries []string)
}

// --- Default Formatter ---
type DefaultFormatter struct {
	showRTT bool
}

func NewDefaultFormatter(showRTT bool) *DefaultFormatter {
	return &DefaultFormatter{showRTT: showRTT}
}

func (f *DefaultFormatter) printRow(ip, mac, rtt, status, vendor string, useColor bool) {
	// Optimización: Uso de strings.Builder si la concatenación fuera muy frecuente,
	// pero aquí Printf con buffer de stdout es suficiente.
	ipStr, macStr, rttStr, statusStr, vendorStr := ip, mac, rtt, status, vendor

	if useColor {
		if ip == "IP Address" {
			ipStr = headerColor(ip)
			macStr = headerColor(mac)
			rttStr = headerColor(rtt)
			statusStr = headerColor(status)
			vendorStr = headerColor(vendor)
		} else {
			ipStr = ipColor(ip)
			macStr = macColor(mac)
			rttStr = rttColor(rtt)
			statusStr = statusColor(status)
			vendorStr = vendorColor(vendor)
		}
	}

	// Padding pre-calculado sería mejor, pero strings.Repeat es rápido para tamaños pequeños.
	ipPadding := strings.Repeat(" ", max(0, ipColWidth-len(ip)))
	macPadding := strings.Repeat(" ", max(0, macColWidth-len(mac)))
	statusPadding := strings.Repeat(" ", max(0, statusColWidth-len(status)))

	if f.showRTT {
		rttPadding := strings.Repeat(" ", max(0, rttColWidth-len(rtt)))
		fmt.Printf("%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
			ipStr, ipPadding, colPadding,
			macStr, macPadding, colPadding,
			rttStr, rttPadding, colPadding,
			statusStr, statusPadding, colPadding,
			vendorStr)
	} else {
		fmt.Printf("%s%s%s%s%s%s%s%s%s%s\n",
			ipStr, ipPadding, colPadding,
			macStr, macPadding, colPadding,
			statusStr, statusPadding, colPadding,
			vendorStr)
	}
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

func (f *DefaultFormatter) PrintHeader() {
	f.printRow("IP Address", "MAC Address", "RTT", "Status", "Vendor", true)
	lineVendor := strings.Repeat("-", 30)
	if f.showRTT {
		f.printRow(strings.Repeat("-", ipColWidth), strings.Repeat("-", macColWidth), strings.Repeat("-", rttColWidth), strings.Repeat("-", statusColWidth), lineVendor, true)
	} else {
		f.printRow(strings.Repeat("-", ipColWidth), strings.Repeat("-", macColWidth), "", strings.Repeat("-", statusColWidth), lineVendor, true)
	}
}

func (f *DefaultFormatter) PrintResult(result scanner.ScanResult) {
	f.printRow(result.IP, result.MAC, result.RTT.String(), result.Status, result.Vendor, true)
}

func (f *DefaultFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	if len(conflictSummaries) > 0 {
		fmt.Println()
		log.Printf(warnColor("ADVERTENCIA: Se detectaron %d conflictos de IP."), len(conflictSummaries))
		for i, summary := range conflictSummaries {
			log.Printf("[%d] %s", i+1, warnColor(summary))
		}
	}
	if len(multiIPSummaries) > 0 {
		fmt.Println()
		log.Printf(infoColor("INFO: Se detectaron %d dispositivos Multi-IP."), len(multiIPSummaries))
		for i, summary := range multiIPSummaries {
			log.Printf("[%d] %s", i+1, infoColor(summary))
		}
	}
}

// --- Quiet Formatter ---
type QuietFormatter struct{}
func NewQuietFormatter() *QuietFormatter { return &QuietFormatter{} }
func (f *QuietFormatter) PrintHeader()   {}
func (f *QuietFormatter) PrintResult(result scanner.ScanResult) {
	fmt.Printf("%s\t%s\n", result.IP, result.MAC)
}
func (f *QuietFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {}

// --- Plain Formatter ---
type PlainFormatter struct { *DefaultFormatter }
func NewPlainFormatter(showRTT bool) *PlainFormatter {
	return &PlainFormatter{DefaultFormatter: NewDefaultFormatter(showRTT)}
}
func (f *PlainFormatter) PrintHeader() {}
func (f *PlainFormatter) PrintResult(result scanner.ScanResult) {
	f.DefaultFormatter.printRow(result.IP, result.MAC, result.RTT.String(), result.Status, result.Vendor, false)
}
func (f *PlainFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {}

// --- CSV Formatter ---
type CSVFormatter struct { writer *csv.Writer }
func NewCSVFormatter() *CSVFormatter { return &CSVFormatter{writer: csv.NewWriter(os.Stdout)} }
func (f *CSVFormatter) PrintHeader() {
	_ = f.writer.Write([]string{"ip", "mac", "rtt_ms", "vendor", "status"})
}
func (f *CSVFormatter) PrintResult(result scanner.ScanResult) {
	_ = f.writer.Write([]string{
		result.IP,
		result.MAC,
		strconv.FormatInt(result.RTT.Milliseconds(), 10),
		result.Vendor,
		result.Status,
	})
}
func (f *CSVFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	f.writer.Flush()
}

// --- JSON Formatter ---
type JSONFormatter struct {
	// Optimización: Almacenamos directamente JSONResult para evitar conversión final masiva
	results []JSONResult
}

func NewJSONFormatter() *JSONFormatter {
	// Pre-alloc conservador
	return &JSONFormatter{results: make([]JSONResult, 0, 100)}
}

func (f *JSONFormatter) PrintHeader() {}

func (f *JSONFormatter) PrintResult(result scanner.ScanResult) {
	f.results = append(f.results, JSONResult{
		IP:     result.IP,
		MAC:    result.MAC,
		RTTms:  result.RTT.Milliseconds(),
		Vendor: result.Vendor,
		Status: result.Status,
	})
}

func (f *JSONFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	output := JSONOutput{
		Results: f.results,
	}
	output.Summary.Conflicts = conflictSummaries
	output.Summary.MultiIP = multiIPSummaries

	// Encoder directo a Stdout es ligeramente más eficiente en memoria que Marshal + Println
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		log.Fatalf("Error fatal al generar la salida JSON: %v", err)
	}
}
