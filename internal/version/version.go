// Package version exposes deterministic EHJINT build identity.
package version

import "runtime"

const (
	// Product is the canonical product name.
	Product = "EHJINT"
	// ProductVersion is the pre-v1 development version.
	ProductVersion = "0.0.0-dev"
)

// Info is the stable Mission 1 build identity.
type Info struct {
	Product        string `json:"product"`
	ProductVersion string `json:"product_version"`
	GoVersion      string `json:"go_version"`
}

// Current returns the build identity without host-specific paths or times.
func Current() Info {
	return Info{
		Product:        Product,
		ProductVersion: ProductVersion,
		GoVersion:      runtime.Version(),
	}
}
