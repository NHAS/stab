// +build embed

package embedCheck

import _ "embed"

//go:embed preload
var EmbeddedBytes []byte
var IsEmbedded bool

func init() {
	IsEmbedded = true
}
