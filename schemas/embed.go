// Package schemas provides embedded CRD schema files
package schemas

import (
	"embed"
)

//go:embed *.yaml
var Schemas embed.FS
