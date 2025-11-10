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

// <-- INICIO BLOQUE MOVILIZADO Y MEJORADO -->

// JSONResult define la estructura de cada resultado individual en la salida JSON.
// Se exporta para ser reutilizada por otros paquetes, como el 'runner' para guardar el estado.
// Usamos tags para controlar los nombres de los campos y 'omitempty' para ocultar campos vacíos.
type JSONResult struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	RTTms  int64  `json:"rtt_ms"`
	Vendor string `json:"vendor"`
	Status string `json:"status,omitempty"`
}

// JSONOutput define la estructura del objeto JSON raíz, que contiene tanto
// los resultados como un resumen del análisis. Se exporta para su reutilización.
type JSONOutput struct {
	Results []JSONResult `json:"results"`
	Summary struct {
		Conflicts []string `json:"conflicts,omitempty"`
		MultiIP   []string `json:"multi_ip,omitempty"`
	} `json:"summary"`
}

// <-- FIN BLOQUE MOVILIZADO Y MEJORADO -->

// Constantes para los anchos de columna.
const (
	ipColWidth     = 15
	macColWidth    = 17
	rttColWidth    = 12
	statusColWidth = 12
	colPadding     = "    "
)

var (
	// Colores de Datos
	ipColor     = color.New(color.FgHiGreen).SprintFunc()
	macColor    = color.New(color.FgHiYellow).SprintFunc()
	vendorColor = color.New(color.FgHiCyan).SprintFunc()
	rttColor    = color.New(color.FgHiMagenta).SprintFunc()
	statusColor = color.New(color.FgHiWhite, color.Bold).SprintFunc() // Blanco brillante y negrita para destacar

	// Colores de Mensajes
	warnColor = color.New(color.FgHiRed).SprintFunc()
	infoColor = color.New(color.FgHiBlue).SprintFunc()

	// Color de Cabecera
	headerColor = color.New(color.FgHiWhite, color.Bold).SprintFunc() // Blanco brillante y negrita
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
	ipStr, macStr, rttStr, statusStr, vendorStr := ip, mac, rtt, status, vendor

	if useColor {
		// ¡OJO! El color de la cabecera es especial.
		// Si estamos imprimiendo la cabecera, usamos headerColor para todo.
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

	ipPadding := strings.Repeat(" ", ipColWidth-len(ip))
	macPadding := strings.Repeat(" ", macColWidth-len(mac))
	statusPadding := strings.Repeat(" ", statusColWidth-len(status))

	if f.showRTT {
		rttPadding := strings.Repeat(" ", rttColWidth-len(rtt))
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
	hasConflicts := len(conflictSummaries) > 0
	hasMultiIPs := len(multiIPSummaries) > 0

	if hasConflicts {
		fmt.Println()
		if len(conflictSummaries) == 1 {
			log.Println(warnColor("ADVERTENCIA: Se detectó 1 conflicto de IP."))
		} else {
			log.Printf(warnColor("ADVERTENCIA: Se detectaron %d conflictos de IP."), len(conflictSummaries))
		}
		for i, summary := range conflictSummaries {
			log.Printf("[%d] %s", i+1, warnColor(summary))
		}
	}

	if hasMultiIPs {
		fmt.Println()
		if len(multiIPSummaries) == 1 {
			log.Println(infoColor("INFO: Se detectó 1 dispositivo Multi-IP."))
		} else {
			log.Printf(infoColor("INFO: Se detectaron %d dispositivos Multi-IP."), len(multiIPSummaries))
		}
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
type PlainFormatter struct {
	*DefaultFormatter
}

func NewPlainFormatter(showRTT bool) *PlainFormatter {
	return &PlainFormatter{DefaultFormatter: NewDefaultFormatter(showRTT)}
}
func (f *PlainFormatter) PrintHeader() {}
func (f *PlainFormatter) PrintResult(result scanner.ScanResult) {
	f.DefaultFormatter.printRow(result.IP, result.MAC, result.RTT.String(), result.Status, result.Vendor, false)
}

func (f *PlainFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	// En modo 'plain', no queremos ningún pie de página, ni siquiera los resúmenes.
}

// --- CSV Formatter ---
type CSVFormatter struct {
	writer *csv.Writer
}

func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{
		writer: csv.NewWriter(os.Stdout),
	}
}

func (f *CSVFormatter) PrintHeader() {
	headers := []string{"ip", "mac", "rtt_ms", "vendor", "status"}
	if err := f.writer.Write(headers); err != nil {
		log.Printf("Error escribiendo la cabecera CSV: %v", err)
	}
}

func (f *CSVFormatter) PrintResult(result scanner.ScanResult) {
	record := []string{
		result.IP,
		result.MAC,
		strconv.FormatInt(result.RTT.Milliseconds(), 10),
		result.Vendor,
		result.Status,
	}
	if err := f.writer.Write(record); err != nil {
		log.Printf("Error escribiendo el registro CSV para %s: %v", result.IP, err)
	}
}

func (f *CSVFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	f.writer.Flush()
	if err := f.writer.Error(); err != nil {
		log.Printf("Error finalizando la escritura CSV: %v", err)
	}
}

// --- JSON Formatter ---
type JSONFormatter struct {
	results []scanner.ScanResult
}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		results: make([]scanner.ScanResult, 0),
	}
}

func (f *JSONFormatter) PrintHeader() {
	// No hacemos nada aquí; la salida JSON se genera toda junta en el footer.
}

func (f *JSONFormatter) PrintResult(result scanner.ScanResult) {
	// Acumulamos los resultados en memoria.
	f.results = append(f.results, result)
}

func (f *JSONFormatter) PrintFooter(conflictSummaries []string, multiIPSummaries []string) {
	output := JSONOutput{}
	output.Summary.Conflicts = conflictSummaries
	output.Summary.MultiIP = multiIPSummaries
	output.Results = make([]JSONResult, len(f.results))

	// Transformamos los resultados del scanner a nuestro formato JSON deseado.
	for i, r := range f.results {
		output.Results[i] = JSONResult{
			IP:     r.IP,
			MAC:    r.MAC,
			RTTms:  r.RTT.Milliseconds(),
			Vendor: r.Vendor,
			Status: r.Status,
		}
	}

	// Serializamos la estructura completa a JSON con indentación.
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Error fatal al generar la salida JSON: %v", err)
	}

	fmt.Println(string(jsonData))
}
