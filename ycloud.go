// Package yubicloud talks to a YubiCloud's authorization server
// Client for https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20
package yubicloud

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Status int

const (
	UNKNOWN_STATUS        = iota
	OK                    // The OTP is valid.
	BAD_OTP               // The OTP is invalid format.
	REPLAYED_OTP          // The OTP has already been seen by the service.
	BAD_SIGNATURE         // The HMAC signature verification failed.
	MISSING_PARAMETER     // The request lacks a parameter.
	NO_SUCH_CLIENT        // The request id does not exist.
	OPERATION_NOT_ALLOWED // The request id is not allowed to verify OTPs.
	BACKEND_ERROR         // Unexpected error in our server. Please contact us if you see this error.
	NOT_ENOUGH_ANSWERS    // Server could not get requested number of syncs during before timeout
	REPLAYED_REQUEST      // Server has seen the OTP/Nonce combination before
)

func statusFromString(status string) Status {
	switch status {
	case "OK":
		return OK
	case "BAD_OTP":
		return BAD_OTP
	case "REPLAYED_OTP":
		return REPLAYED_OTP
	case "BAD_SIGNATURE":
		return BAD_SIGNATURE
	case "MISSING_PARAMETER":
		return MISSING_PARAMETER
	case "NO_SUCH_CLIENT":
		return NO_SUCH_CLIENT
	case "OPERATION_NOT_ALLOWED":
		return OPERATION_NOT_ALLOWED
	case "BACKEND_ERROR":
		return BACKEND_ERROR
	case "NOT_ENOUGH_ANSWERS":
		return NOT_ENOUGH_ANSWERS
	case "REPLAYED_REQUEST":
		return REPLAYED_REQUEST
	}

	return UNKNOWN_STATUS
}

var YubiCloudServers = []string{
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify",
}

type YubiClient struct {
	ApiKey  string
	Servers []string
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
	return u
}

type VerifyResponse struct {
	OTP            string
	Nonce          string
	H              []byte
	T              time.Time // timestamp
	Status         Status
	Timestamp      string
	SessionCounter string
	SessionUse     string
	SL             int
}

func New() *YubiClient {
	return &YubiClient{Servers: YubiCloudServers}
}

// Why couldn't they just use a standard format?
// https://github.com/Yubico/yubikey-val/blob/master/ykval-common.php  getUTCTimestamp()
func parseTimestamp(t string) time.Time {
	milli, _ := strconv.Atoi(t[len(t)-3:])
	t = t[:len(t)-3]
	ts, err := time.Parse("2006-01-02T15:04:05Z0", t)
	if err != nil {
		log.Println("error parsing timestamp:", err)
		return time.Time{}
	}
	// FIXME: don't think this is right, need to check against PHP
	return ts.Add(time.Duration(milli) * time.Millisecond)
}

func responseFromBody(body []byte) (*VerifyResponse, error) {

	buf := bytes.NewBuffer(body)

	scanner := bufio.NewScanner(buf)

	m := make(map[string]string)

	// Validate the input
	for scanner.Scan() {
		l := scanner.Bytes()
		s := bytes.Split(l, []byte{'='})
		if s == nil || len(s) == 0 || len(s) == 1 && len(s[0]) == 0 {
			continue
		}
		m[string(s[0])] = string(s[1])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	r := &VerifyResponse{}
	r.OTP = m["otp"]
	r.Nonce = m["nonce"]
	r.H = []byte(m["h"]) // FIXME: de-base64 ? and verify hash
	r.T = parseTimestamp(m["t"])
	r.Status = statusFromString(string(m["status"]))
	var err error
	r.SL, err = strconv.Atoi(m["sl"])
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	// optional responses
	if s, ok := m["timestamp"]; ok {
		r.Timestamp = s
	}

	if s, ok := m["sessioncounter"]; ok {
		r.SessionCounter = s
	}

	if s, ok := m["sessionuse"]; ok {
		r.SessionUse = s
	}

	return r, nil
}

func (y *YubiClient) Verify(req *VerifyRequest) (*VerifyResponse, error) {

	// random server
	server := y.Servers[rand.Intn(len(y.Servers))]

	resp, err := http.PostForm(server, req.toValues())

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response, err := responseFromBody(body)

	if err != nil {
		return nil, err
	}

	// FIXME: validate response
	if response.OTP != req.OTP {
		return nil, errors.New("response OTP does not match")
	}
	if response.Nonce != req.Nonce {
		return nil, errors.New("response Nonce does not match")
	}

	// FIXME: validate signature if we have an API key

	return response, nil
}
