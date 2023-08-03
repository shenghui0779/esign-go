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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// Client E签宝客户端
type Client struct {
	host    string
	appid   string
	secret  string
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// SetHTTPClient 设置自定义Client
func (c *Client) SetHTTPClient(cli *http.Client) {
	c.httpCli = NewHTTPClient(cli)
}

// WithLogger 设置日志记录
func (c *Client) WithLogger(f func(ctx context.Context, data map[string]string)) {
	c.logger = f
}

// URL 生成请求URL
func (c *Client) URL(path string, query url.Values) string {
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
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, options ...HTTPOption) (gjson.Result, error) {
	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	reqHeader := http.Header{}

	reqHeader.Set("Accept", Accept)
	reqHeader.Set("X-Tsign-Open-App-Id", c.appid)
	reqHeader.Set("X-Tsign-Open-Auth-Mode", AuthMode)
	reqHeader.Set("X-Tsign-Open-Ca-Signature", NewSigner(http.MethodGet, path, WithSignValues(query)).Do(c.secret))
	reqHeader.Set("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodGet, reqURL, nil, httpOptions...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("code").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("message")))
	}

	return ret.Get("data"), nil
}

// PostJSON POST请求JSON数据
func (c *Client) PostJSON(ctx context.Context, path string, params X, options ...HTTPOption) (gjson.Result, error) {
	reqURL := c.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return fail(err)
	}

	log.SetReqBody(string(body))

	contentMD5 := ContentMD5(body)

	reqHeader := http.Header{}

	reqHeader.Set("Accept", Accept)
	reqHeader.Set("Content-Type", ContentJSON)
	reqHeader.Set("Content-MD5", contentMD5)
	reqHeader.Set("X-Tsign-Open-App-Id", c.appid)
	reqHeader.Set("X-Tsign-Open-Auth-Mode", AuthMode)
	reqHeader.Set("X-Tsign-Open-Ca-Signature", NewSigner(http.MethodPost, path, WithSignContMD5(contentMD5), WithSignContType(ContentJSON)).Do(c.secret))
	reqHeader.Set("X-Tsign-Open-Ca-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, body, httpOptions...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("code").Int(); code != 0 {
		return fail(fmt.Errorf("%d | %s", code, ret.Get("message")))
	}

	return ret.Get("data"), nil
}

// PutStream 上传文件流
func (c *Client) PutStream(ctx context.Context, uploadURL string, reader io.ReadSeeker, options ...HTTPOption) error {
	log := NewReqLog(http.MethodPut, uploadURL)
	defer log.Do(ctx, c.logger)

	// 文件指针移动到头部
	if _, err := reader.Seek(0, 0); err != nil {
		return err
	}

	h := md5.New()

	if _, err := io.Copy(h, reader); err != nil {
		return err
	}

	reqHeader := http.Header{}

	reqHeader.Set("Content-Type", ContentStream)
	reqHeader.Set("Content-MD5", base64.StdEncoding.EncodeToString(h.Sum(nil)))

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	// 文件指针移动到头部
	if _, err := reader.Seek(0, 0); err != nil {
		return err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb

	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(), httpOptions...)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errCode").Int(); code != 0 {
		return fmt.Errorf("%d | %s", code, ret.Get("msg"))
	}

	return nil
}

func (c *Client) PutStreamFromFile(ctx context.Context, uploadURL, filename string, options ...HTTPOption) error {
	log := NewReqLog(http.MethodPut, uploadURL)
	defer log.Do(ctx, c.logger)

	f, err := os.Open(filename)

	if err != nil {
		return err
	}

	defer f.Close()

	h := md5.New()

	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	reqHeader := http.Header{}

	reqHeader.Set("Content-Type", ContentStream)
	reqHeader.Set("Content-MD5", base64.StdEncoding.EncodeToString(h.Sum(nil)))

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	// 文件指针移动到头部
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb

	if _, err := io.Copy(buf, f); err != nil {
		return err
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(), httpOptions...)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	log.SetRespBody(string(b))

	ret := gjson.ParseBytes(b)

	if code := ret.Get("errCode").Int(); code != 0 {
		return fmt.Errorf("%d | %s", code, ret.Get("msg"))
	}

	return nil
}

// Verify 签名验证 (回调通知等)
func (c *Client) Verify(header http.Header, body []byte) error {
	appid := header.Get("X-Tsign-Open-App-Id")
	timestamp := header.Get("X-Tsign-Open-TIMESTAMP")
	sign := header.Get("X-Tsign-Open-SIGNATURE")

	if appid != c.appid {
		return fmt.Errorf("appid mismatch, expect = %s, actual = %s", c.appid, appid)
	}

	h := hmac.New(sha256.New, []byte(c.secret))
	h.Write([]byte(timestamp))
	h.Write(body)

	if v := hex.EncodeToString(h.Sum(nil)); v != sign {
		return fmt.Errorf("signature mismatch, expect = %s, actual = %s", v, sign)
	}

	return nil
}

// NewClient 返回E签宝客户端
func NewClient(appid, secret string) *Client {
	return &Client{
		host:    "https://openapi.esign.cn",
		appid:   appid,
		secret:  secret,
		httpCli: NewDefaultHTTPClient(),
	}
}

// NewSandbox 返回E签宝「沙箱环境」客户端
func NewSandbox(appid, secret string) *Client {
	return &Client{
		host:    "https://smlopenapi.esign.cn",
		appid:   appid,
		secret:  secret,
		httpCli: NewDefaultHTTPClient(),
	}
}
