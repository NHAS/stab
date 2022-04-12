// +build !embed

package embedCheck

var EmbeddedBytes []byte
var IsEmbedded bool

func init() {
	IsEmbedded = false
}
