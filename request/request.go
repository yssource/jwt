package request

import (
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// ParseFromRequest extracts and parses a JWT token from an HTTP request.
// This behaves the same as Parse, but accepts a request and an extractor
// instead of a token string.  The Extractor interface allows you to define
// the logic for extracting a token.  Several useful implementations are provided.
//
// You can provide options to modify parsing behavior
func ParseFromRequest[T jwt.Key](req *http.Request, extractor Extractor, keyFunc jwt.Keyfunc[T], options ...ParseFromRequestOption[T]) (token *jwt.Token[T], err error) {
	// Create basic parser struct
	p := &fromRequestParser[T]{req, extractor, nil, nil}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.claims == nil {
		p.claims = jwt.MapClaims{}
	}
	if p.parser == nil {
		p.parser = &jwt.Parser[T]{}
	}

	// perform extract
	tokenString, err := p.extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	// perform parse
	return p.parser.ParseWithClaims(tokenString, p.claims, keyFunc)
}

// ParseFromRequestWithClaims is an alias for ParseFromRequest but with custom Claims type.
//
// Deprecated: use ParseFromRequest and the WithClaims option
func ParseFromRequestWithClaims[T jwt.Key](req *http.Request, extractor Extractor, claims jwt.Claims, keyFunc jwt.Keyfunc[T]) (token *jwt.Token[T], err error) {
	return ParseFromRequest(req, extractor, keyFunc, WithClaims[T](claims))
}

type fromRequestParser[T jwt.Key] struct {
	req       *http.Request
	extractor Extractor
	claims    jwt.Claims
	parser    *jwt.Parser[T]
}

type ParseFromRequestOption[T jwt.Key] func(*fromRequestParser[T])

// WithClaims parses with custom claims
func WithClaims[T jwt.Key](claims jwt.Claims) ParseFromRequestOption[T] {
	return func(p *fromRequestParser[T]) {
		p.claims = claims
	}
}

// WithParser parses using a custom parser
func WithParser[T jwt.Key](parser *jwt.Parser[T]) ParseFromRequestOption[T] {
	return func(p *fromRequestParser[T]) {
		p.parser = parser
	}
}
