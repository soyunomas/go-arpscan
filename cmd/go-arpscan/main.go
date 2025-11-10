// cmd/go-arpscan/main.go
package main

import (
	"math/rand"
	"os"
	"time"
)

// main es el único punto de entrada de la aplicación.
// Su única responsabilidad es inicializar el generador de números aleatorios
// y ejecutar el comando raíz de Cobra.
func main() {
	// Seed del generador de números aleatorios para funcionalidades como la aleatorización de MACs en perfiles.
	rand.Seed(time.Now().UnixNano())

	if err := Execute(); err != nil {
		os.Exit(1)
	}
}
