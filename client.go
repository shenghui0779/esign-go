package esign

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// ESignClient E签宝客户端
type ESignClient struct {
	host   string
	appid  string
	secret string
	client HTTPClient
}

// SetHTTPClient 设置 HTTP Client
func (c *ESignClient) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
}

// URL 生成请求URL
func (c *ESignClient) URL(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(c.host)

	if len(path) != 0 && path[0] != '/' {
		builder.WriteString("/")
	}

	builder.WriteString(path)

	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}

	return builder.String()
}

// GetJSON GET请求JSON数据
func (c *ESignClient) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (gjson.Result, error) {
	sign := NewSigner(http.MethodGet, path, WithSignValues(query)).Do(c.secret)

	options = append(options, WithHTTPHeader("Accept", Accept),
		WithHTTPHeader("X-Tsign-Open-App-Id", c.appid),
		WithHTTPHeader("X-Tsign-Open-Auth-Mode", AuthMode),
		WithHTTPHeader("X-Tsign-Open-Ca-Signature", sign),
		WithHTTPHeader("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10)),
	)

	resp, err := c.client.Do(ctx, http.MethodGet, c.URL(path, query), nil, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("unexpected http status: %d", resp.StatusCode))
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

// PostJSON POST请求JSON数据
func (c *ESignClient) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (gjson.Result, error) {
	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	contentMD5 := ContentMD5(body)

	sign := NewSigner(http.MethodPost, path, WithSignContMD5(contentMD5), WithSignContType(ContentJSON)).Do(c.secret)

	options = append(options, WithHTTPHeader("Accept", Accept),
		WithHTTPHeader("Content-Type", ContentJSON),
		WithHTTPHeader("Content-MD5", contentMD5),
		WithHTTPHeader("X-Tsign-Open-App-Id", c.appid),
		WithHTTPHeader("X-Tsign-Open-Auth-Mode", AuthMode),
		WithHTTPHeader("X-Tsign-Open-Ca-Signature", sign),
		WithHTTPHeader("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10)),
	)

	resp, err := c.client.Do(ctx, http.MethodPost, c.URL(path, nil), body, options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("unexpected http status: %d", resp.StatusCode))
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

// PutStream 上传文件流
func (c *ESignClient) PutStream(ctx context.Context, uploadURL, filename string, options ...HTTPOption) error {
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

	options = append(options, WithHTTPHeader("Content-Type", ContentStream), WithHTTPHeader("Content-MD5", base64.StdEncoding.EncodeToString(h.Sum(nil))))

	resp, err := c.client.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(), options...)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status: %d", resp.StatusCode)
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

// Verify 签名验证 (回调通知等)
func (c *ESignClient) Verify(header http.Header, body []byte) error {
	appid := header.Get("X-Tsign-Open-App-Id")
	timestamp := header.Get("X-Tsign-Open-TIMESTAMP")
	sign := header.Get("X-Tsign-Open-SIGNATURE")

	if appid != c.appid {
		return fmt.Errorf("appid mismatch, expect: %s, actual: %s", c.appid, appid)
	}

	h := hmac.New(sha256.New, []byte(c.secret))
	h.Write([]byte(timestamp))
	h.Write(body)

	if v := hex.EncodeToString(h.Sum(nil)); v != sign {
		return fmt.Errorf("signature mismatch, expect: %s, actual: %s", v, sign)
	}

	return nil
}

// NewESignClient 返回E签宝客户端
func NewESignClient(appid, secret string) *ESignClient {
	return &ESignClient{
		host:   "https://openapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: NewDefaultHTTPClient(),
	}
}

// NewESignSandboxClient 返回E签宝「沙箱环境」客户端
func NewESignSandboxClient(appid, secret string) *ESignClient {
	return &ESignClient{
		host:   "https://smlopenapi.esign.cn",
		appid:  appid,
		secret: secret,
		client: NewDefaultHTTPClient(),
	}
}
