package esign_v2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestV(t *testing.T) {
	v1 := V{}

	v1.Set("bar", "baz")
	v1.Set("foo", "quux")

	assert.Equal(t, "bar=baz&foo=quux", v1.Encode("=", "&"))
	assert.Equal(t, "bar:baz#foo:quux", v1.Encode(":", "#"))

	v2 := V{}

	v2.Set("bar", "baz@666")
	v2.Set("foo", "quux%666")

	assert.Equal(t, "bar=baz%40666&foo=quux%25666", v2.Encode("=", "&", WithKVEscape()))
	assert.Equal(t, "bar:baz%40666#foo:quux%25666", v2.Encode(":", "#", WithKVEscape()))

	v3 := V{}

	v3.Set("bar", "baz")
	v3.Set("foo", "")

	assert.Equal(t, "bar=baz&foo=", v3.Encode("=", "&"))
	assert.Equal(t, "bar=baz&foo=", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeDefault)))
	assert.Equal(t, "bar=baz&foo", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeOnlyKey)))
	assert.Equal(t, "bar=baz", v3.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeIgnore)))
}
