package esign_v2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

type signfields struct {
	accept      string
	contentMD5  string
	contentType string
	date        string
	headers     V
	params      V
}

type SignOption func(sf *signfields)

func WithSignAccept(v string) SignOption {
	return func(sf *signfields) {
		sf.accept = v
	}
}

func WithSignContentMD5(v string) SignOption {
	return func(sf *signfields) {
		sf.contentMD5 = v
	}
}

func WithSignContentType(v string) SignOption {
	return func(sf *signfields) {
		sf.contentType = v
	}
}

func WithSignDate(v string) SignOption {
	return func(sf *signfields) {
		sf.date = v
	}
}

func WithSignHeader(k, v string) SignOption {
	return func(sf *signfields) {
		sf.headers.Set(k, v)
	}
}

func WithSignParam(k, v string) SignOption {
	return func(sf *signfields) {
		sf.params.Set(k, v)
	}
}

func WithSignValues(v url.Values) SignOption {
	return func(sf *signfields) {
		for key, vals := range v {
			if len(vals) != 0 {
				sf.params.Set(key, vals[0])
			} else {
				sf.params.Set(key, "")
			}
		}
	}
}

type Signer struct {
	str string
}

func (s *Signer) Do(secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(s.str))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (s *Signer) String() string {
	return s.str
}

func NewSigner(method, path string, options ...SignOption) *Signer {
	fields := &signfields{
		accept:  "*/*",
		headers: V{},
		params:  V{},
	}

	for _, f := range options {
		f(fields)
	}

	var buf strings.Builder

	buf.WriteString(method)
	buf.WriteString("\n")
	buf.WriteString(fields.accept)
	buf.WriteString("\n")
	buf.WriteString(fields.contentMD5)
	buf.WriteString("\n")
	buf.WriteString(fields.contentType)
	buf.WriteString("\n")
	buf.WriteString(fields.date)
	buf.WriteString("\n")

	if len(fields.headers) != 0 {
		buf.WriteString(fields.headers.Encode(":", "\n"))
		buf.WriteString("\n")
	}

	buf.WriteString(path)

	if len(fields.params) != 0 {
		buf.WriteString("?")
		buf.WriteString(fields.params.Encode("=", "&", WithEmptyEncodeMode(EmptyEncodeOnlyKey)))
	}

	return &Signer{str: buf.String()}
}
