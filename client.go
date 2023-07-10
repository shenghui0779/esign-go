package esign_v2

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/tidwall/gjson"
)

type ESignClient struct {
	host   string
	appid  string
	secret string
	client HTTPClient
}

func (esc *ESignClient) GetJSON(ctx context.Context, path string, query url.Values) (gjson.Result, error) {
	fail := func(err error) (gjson.Result, error) { return gjson.Result{}, err }

	sign := NewSigner(http.MethodGet, path, WithValues(query)).Do(esc.secret)

	reqURL := esc.host + path

	if len(query) != 0 {
		reqURL = reqURL + "?" + query.Encode()
	}

	resp, err := esc.client.Do(ctx, http.MethodGet, reqURL, nil,
		WithHTTPHeader("Accept", Accept),
		WithHTTPHeader("X-Tsign-Open-App-Id", esc.appid),
		WithHTTPHeader("X-Tsign-Open-Auth-Mode", AuthMode),
		WithHTTPHeader("X-Tsign-Open-Ca-Signature", sign),
		WithHTTPHeader("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10)),
	)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("err http status: %d", resp.StatusCode))
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("code").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("message")))
	}

	return ret.Get("data"), nil
}

func (esc *ESignClient) PostJSON(ctx context.Context, path string, params X) (gjson.Result, error) {
	fail := func(err error) (gjson.Result, error) { return gjson.Result{}, err }

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	contentMD5 := ContentMD5(body)

	sign := NewSigner(http.MethodPost, path, WithContentMD5(contentMD5), WithContentType(ContentJSON)).Do(esc.secret)

	reqURL := esc.host + path

	resp, err := esc.client.Do(ctx, http.MethodPost, reqURL, body,
		WithHTTPHeader("Accept", Accept),
		WithHTTPHeader("Content-Type", ContentJSON),
		WithHTTPHeader("Content-MD5", contentMD5),
		WithHTTPHeader("X-Tsign-Open-App-Id", esc.appid),
		WithHTTPHeader("X-Tsign-Open-Auth-Mode", AuthMode),
		WithHTTPHeader("X-Tsign-Open-Ca-Signature", sign),
		WithHTTPHeader("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10)),
	)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("err http status: %d", resp.StatusCode))
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("code").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("message")))
	}

	return ret.Get("data"), nil
}

func (esc *ESignClient) PutStream(ctx context.Context, uploadURL, filename string) error {
	f, err := os.Open(filename)

	if err != nil {
		return err
	}

	defer f.Close()

	h := md5.New()

	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	f.Seek(0, 0)

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb

	if _, err := io.Copy(buf, f); err != nil {
		return err
	}

	resp, err := esc.client.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(),
		WithHTTPHeader("Content-Type", ContentStream),
		WithHTTPHeader("Content-MD5", base64.StdEncoding.EncodeToString(h.Sum(nil))),
	)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("err http status: %d", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errCode").Int(); code != 0 {
		return fmt.Errorf("%d | %s", code, ret.Get("msg"))
	}

	return nil
}

type ESignOption func(esc *ESignClient)

func WithHTTPClient(client *http.Client) ESignOption {
	return func(esc *ESignClient) {
		esc.client = NewHTTPClient(client)
	}
}

func NewESignClient(host, appid, secret string, options ...ESignOption) *ESignClient {
	esc := &ESignClient{
		host:   host,
		appid:  appid,
		secret: secret,
		client: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(esc)
	}

	return esc
}
