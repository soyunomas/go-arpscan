// internal/formatter/formatter.go
package formatter

import (
	"fmt"
	"go-arpscan/internal/scanner"
	"log"
	"strings"

	"github.com/fatih/color"
)

// Constantes para los anchos de columna.
const (
	ipColWidth     = 15
	macColWidth    = 17
	rttColWidth    = 12
	statusColWidth = 12
	colPadding     = "    "
)

// <-- INICIO BLOQUE MODIFICADO: PALETA DE COLORES REVISADA Y MÁS BRILLANTE -->
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
// <-- FIN BLOQUE MODIFICADO -->

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
	f.DefaultFormatter.PrintFooter(conflictSummaries, multiIPSummaries)
}
