package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// DecodePaddingAllowed will switch the codec used for decoding JWTs respectively. Note that the JWS RFC7515
// states that the tokens will utilize a Base64url encoding with no padding. Unfortunately, some implementations
// of JWT are producing non-standard tokens, and thus require support for decoding. Note that this is a global
// variable, and updating it will change the behavior on a package level, and is also NOT go-routine safe.
// To use the non-recommended decoding, set this boolean to `true` prior to using this package.
var DecodePaddingAllowed bool

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
// You can override it to use another time value.  This is useful for testing or if your
// server uses a different time zone than your tokens.
var TimeFunc = time.Now

// Keyfunc will be used by the Parse methods as a callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
type Keyfunc[T Key] func(*Token[T]) (T, error)

type Key interface {
	[]byte |
		*rsa.PublicKey |
		*ecdsa.PublicKey |
		*ed25519.PublicKey |
		ed25519.PublicKey |
		unsafeNoneMagicConstant |
		crypto.PublicKey // TODO: get rid of any in the future
}

// Token represents a JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token[T Key] struct {
	Raw       string                 // The raw token.  Populated when you Parse a token
	Method    SigningMethod[T]       // The signing method used or to be used
	Header    map[string]interface{} // The first segment of the token
	Claims    Claims                 // The second segment of the token
	Signature string                 // The third segment of the token.  Populated when you Parse a token
	Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token
}

// New creates a new Token with the specified signing method and an empty map of claims.
func New[T Key](method SigningMethod[T]) *Token[T] {
	return NewWithClaims(method, MapClaims{})
}

// NewWithClaims creates a new Token with the specified signing method and claims.
func NewWithClaims[T Key](method SigningMethod[T], claims Claims) *Token[T] {
	return &Token[T]{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: claims,
		Method: method,
	}
}

// SignedString creates and returns a complete, signed JWT.
// The token is signed using the SigningMethod specified in the token.
func (t *Token[T]) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// SigningString generates the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func (t *Token[T]) SigningString() (string, error) {
	var err error
	var jsonValue []byte

	if jsonValue, err = json.Marshal(t.Header); err != nil {
		return "", err
	}
	header := EncodeSegment(jsonValue)

	if jsonValue, err = json.Marshal(t.Claims); err != nil {
		return "", err
	}
	claim := EncodeSegment(jsonValue)

	return strings.Join([]string{header, claim}, "."), nil
}

// Parse parses, validates, verifies the signature and returns the parsed token.
// keyFunc will receive the parsed token and should return the cryptographic key
// for verifying the signature.
// The caller is strongly encouraged to set the WithValidMethods option to
// validate the 'alg' claim in the token matches the expected algorithm.
// For more details about the importance of validating the 'alg' claim,
// see https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func Parse[T Key](tokenString string, keyFunc Keyfunc[T], options ...ParserOption[T]) (*Token[T], error) {
	return NewParser(options...).Parse(tokenString, keyFunc)
}

func ParseWithClaims[T Key](tokenString string, claims Claims, keyFunc Keyfunc[T], options ...ParserOption[T]) (*Token[T], error) {
	return NewParser(options...).ParseWithClaims(tokenString, claims, keyFunc)
}

// EncodeSegment encodes a JWT specific base64url encoding with padding stripped
//
// Deprecated: In a future release, we will demote this function to a non-exported function, since it
// should only be used internally
func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

// DecodeSegment decodes a JWT specific base64url encoding with padding stripped
//
// Deprecated: In a future release, we will demote this function to a non-exported function, since it
// should only be used internally
func DecodeSegment(seg string) ([]byte, error) {
	if DecodePaddingAllowed {
		if l := len(seg) % 4; l > 0 {
			seg += strings.Repeat("=", 4-l)
		}
		return base64.URLEncoding.DecodeString(seg)
	}

	return base64.RawURLEncoding.DecodeString(seg)
}
