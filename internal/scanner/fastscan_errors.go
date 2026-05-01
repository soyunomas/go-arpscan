// internal/scanner/fastscan_errors.go
package scanner

import "errors"

var errFastUnsupported = errors.New("fastscan: fast engine is only supported on Linux")
