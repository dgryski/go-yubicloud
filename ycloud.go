// Package yubicloud talks to a YubiCloud's authorization server
// Client for https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20
package yubicloud

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type Status int

const (
	UNKNOWN_STATUS        Status = iota
	OK                           // The OTP is valid.
	BAD_OTP                      // The OTP is invalid format.
	REPLAYED_OTP                 // The OTP has already been seen by the service.
	BAD_SIGNATURE                // The HMAC signature verification failed.
	MISSING_PARAMETER            // The request lacks a parameter.
	NO_SUCH_CLIENT               // The request id does not exist.
	OPERATION_NOT_ALLOWED        // The request id is not allowed to verify OTPs.
	BACKEND_ERROR                // Unexpected error in our server. Please contact us if you see this error.
	NOT_ENOUGH_ANSWERS           // Server could not get requested number of syncs during before timeout
	REPLAYED_REQUEST             // Server has seen the OTP/Nonce combination before
)

var statusStrings = []string{
	"UNKNOWN_STATUS",
	"OK",
	"BAD_OTP",
	"REPLAYED_OTP",
	"BAD_SIGNATURE",
	"MISSING_PARAMETER",
	"NO_SUCH_CLIENT",
	"OPERATION_NOT_ALLOWED",
	"BACKEND_ERROR",
	"NOT_ENOUGH_ANSWERS",
	"REPLAYED_REQUEST",
}

func (s Status) String() string {
	i := int(s)
	if i < 0 || len(statusStrings) <= i {
		i = 0
	}
	return statusStrings[i]
}

func statusFromString(status string) Status {
	for i, s := range statusStrings {
		if status == s {
			return Status(i)
		}

	}
	return UNKNOWN_STATUS
}

func (s Status) IsError() bool {
	return s == BACKEND_ERROR || s == BAD_OTP || s == BAD_SIGNATURE || s == NO_SUCH_CLIENT || s == MISSING_PARAMETER
}

var YubiCloudServers = []string{
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify",
}

type YubiClient struct {
	id      string
	apiKey  []byte
	servers []string
}

type VerifyRequest struct {
	ID        string
	OTP       string
	H         string
	Timestamp bool
	Nonce     string
	SL        string
	Timeout   int
}

func (v *VerifyRequest) toValues() url.Values {
	u := url.Values{
		"id":    {v.ID},
		"otp":   {v.OTP},
		"nonce": {v.Nonce},
	}

	if v.Timestamp {
		u["timestamp"] = []string{"1"}
	}

	if v.SL != "" {
		u["sl"] = []string{v.SL}
	}

	if v.Timeout != 0 {
		u["timeout"] = []string{strconv.Itoa(v.Timeout)}
	}

	return u
}

func isValidResponseHash(m map[string]string, key []byte) bool {

	// if we have no API key, or no hash was provided, then it's valid
	if key == nil || len(key) == 0 || m["h"] == "" {
		return true
	}

	exp, err := base64.StdEncoding.DecodeString(m["h"])
	if err != nil {
		return false
	}

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := hmac.New(sha1.New, key)
	var ampersand []byte
	for _, k := range keys {
		if k == "h" {
			continue
		}
		h.Write(ampersand)
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(m[k]))
		ampersand = []byte{'&'}
	}

	return hmac.Equal(exp, h.Sum(nil))
}

func signRequest(req url.Values, key []byte) {
	h := hmac.New(sha1.New, key)
	u := req.Encode()
	h.Write([]byte(u))
	sig := h.Sum(nil)
	req["h"] = []string{base64.StdEncoding.EncodeToString(sig)}
}

type VerifyResponse struct {
	OTP            string
	Nonce          string
	H              []byte
	T              time.Time // timestamp
	Status         Status
	Timestamp      uint
	SessionCounter uint
	SessionUse     uint
	SL             int
}

func New(id string, apikey string) (*YubiClient, error) {
	return NewWithServers(id, apikey, YubiCloudServers)
}

func NewWithServers(id string, apikey string, servers []string) (*YubiClient, error) {
	y := &YubiClient{id: id, servers: servers}
	if apikey != "" {
		key, err := base64.StdEncoding.DecodeString(apikey)
		if err != nil {
			return nil, err
		}
		y.apiKey = key
	}

	return y, nil
}

// Why couldn't they just use a standard format?
// https://github.com/Yubico/yubikey-val/blob/master/ykval-common.php  getUTCTimestamp()
func parseTimestamp(t string) (time.Time, error) {
	milli, _ := strconv.Atoi(t[len(t)-3:])
	t = t[:len(t)-3]
	ts, err := time.Parse("2006-01-02T15:04:05Z0", t)
	if err != nil {
		return time.Time{}, err
	}
	return ts.Add(time.Duration(milli) * time.Millisecond), nil
}

func (y *YubiClient) responseFromBody(body []byte) (*VerifyResponse, error) {

	buf := bytes.NewBuffer(body)

	scanner := bufio.NewScanner(buf)

	m := make(map[string]string)

	// Validate the input
	for scanner.Scan() {
		l := scanner.Bytes()
		s := bytes.SplitN(l, []byte{'='}, 2)
		if s == nil || len(s) == 0 || len(s) != 2 {
			continue
		}
		m[string(s[0])] = string(s[1])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	if !isValidResponseHash(m, y.apiKey) {
		return nil, fmt.Errorf("invalid response signature")
	}

	var err error
	r := &VerifyResponse{}
	r.OTP = m["otp"]
	r.Nonce = m["nonce"]
	r.H, _ /* err */ = base64.StdEncoding.DecodeString(m["h"]) // error ignored here because it validated in isValidResponseHash()
	r.T, err = parseTimestamp(m["t"])
	if err != nil {
		return nil, fmt.Errorf("error parsing response timestamp: %s", err)
	}

	r.Status = statusFromString(string(m["status"]))
	if sl, ok := m["sl"]; ok {
		r.SL, err = strconv.Atoi(sl)
		if err != nil {
			return nil, fmt.Errorf("error parsing response `sl': %s", err)
		}
	}

	// optional responses
	if s, ok := m["timestamp"]; ok {
		sc, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("error parsing timestamp: %s", err)
		}
		r.Timestamp = uint(sc)
	}

	if s, ok := m["sessioncounter"]; ok {
		sc, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sessioncounter: %s", err)
		}
		r.SessionCounter = uint(sc)
	}

	if s, ok := m["sessionuse"]; ok {
		sc, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("error parsing sessionuse: %s", err)
		}
		r.SessionUse = uint(sc)
	}

	return r, nil
}

func (y *YubiClient) Verify(req *VerifyRequest) (*VerifyResponse, error) {

	// random server
	server := y.servers[rand.Intn(len(y.servers))]

	if req.ID == "" {
		req.ID = y.id
	}

	values := req.toValues()

	if y.apiKey != nil {
		signRequest(values, y.apiKey)
	}

	resp, err := http.PostForm(server, values)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response, err := y.responseFromBody(body)

	if err != nil {
		return nil, err
	}

	// Invalid values don't return the Nonce
	if response.Nonce == "" && response.Status.IsError() {
		return response, nil
	}

	if response.Nonce != req.Nonce {
		return nil, errors.New("response Nonce does not match")
	}

	return response, nil
}
