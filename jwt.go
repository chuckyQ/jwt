// Heavily copied from here: https://github.com/golang-jwt/jwt/blob/main/hmac.go.
// We only support one signing method.

package jwt

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
)

type token struct {
	Header map[string]string // Header is the first segment of the token in decoded form
	Claims map[string]any    // Claims is the second segment of the token in decoded form
}

const hashFn = crypto.SHA256
const hashName = "HS256"

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

func (t *token) signedString(secret []byte) (string, error) {
	sstr, err := t.signingString()
	if err != nil {
		return "", err
	}

	hm := hmac.New(hashFn.New, secret)
	_, err = hm.Write([]byte(sstr))
	if err != nil {
		return "", err
	}

	sum := hm.Sum(nil)

	seg := encodeSegment(sum)
	return sstr + "." + seg, nil
}

func (t *token) expired() bool {

	now := time.Now().Unix()

	// For some reason, this has to be a float64
	// comparison even though we only work with
	// int64s.

	expiration, ok := t.Claims["exp"]

	if !ok {
		return true
	}

	if exp, ok := expiration.(float64); ok {
		return exp < float64(now)
	}

	return true

}

func (t *token) signingString() (string, error) {

	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	return encodeSegment(h) + "." + encodeSegment(c), nil
}

// VerifyJWT verifies a given JWT and checks if it is expired.
func VerifyJWT(jwt string, secret []byte) (bool, map[string]string, map[string]any, error) {

	parts := strings.Split(jwt, ".")

	if len(parts) != 3 {
		return false, nil, nil, errors.New("JWT does not have 3 parts")
	}

	tok := &token{}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, nil, nil, err
	}
	if err = json.Unmarshal(headerBytes, &tok.Header); err != nil {
		return false, nil, nil, err
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil, nil, err
	}

	if err = json.Unmarshal(claimBytes, &tok.Claims); err != nil {
		return false, nil, nil, err
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])

	if err != nil {
		return false, nil, nil, err
	}

	h := hmac.New(hashFn.New, secret)
	sstr, err := tok.signingString()

	if err != nil {
		return false, nil, nil, err
	}

	h.Write([]byte(sstr))
	sum := h.Sum(nil)
	return hmac.Equal(signatureBytes, sum) && !tok.expired(), tok.Header, tok.Claims, nil

}

// makeJWT is used for creating a JWT.
func New(claims map[string]any, timeout int, secret []byte) (string, error) {

	if timeout <= 0 {
		return "", errors.New("timeout must be > 0")
	}

	headers := make(map[string]string)
	headers["typ"] = "JWT"
	headers["alg"] = hashName

	m := maps.Clone(claims)

	now := int(time.Now().Unix())
	m["iss"] = now
	m["exp"] = now + timeout

	t := token{
		Header: headers,
		Claims: m,
	}

	return t.signedString(secret)
}
