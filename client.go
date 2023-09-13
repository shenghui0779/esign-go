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

	reqHeader.Set(HeaderAccept, AcceptAll)
	reqHeader.Set(HeaderTSignOpenAppID, c.appid)
	reqHeader.Set(HeaderTSignOpenAuthMode, AuthModeSign)
	reqHeader.Set(HeaderTSignOpenCaTimestamp, strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqHeader.Set(HeaderTSignOpenCaSignature, NewSigner(http.MethodGet, path, WithSignValues(query)).Do(c.secret))

	log.SetReqHeader(reqHeader)

	resp, err := c.httpCli.Do(ctx, http.MethodGet, reqURL, nil, HeaderToHttpOption(reqHeader)...)
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

	reqHeader.Set(HeaderAccept, AcceptAll)
	reqHeader.Set(HeaderContentType, ContentJSON)
	reqHeader.Set(HeaderContentMD5, contentMD5)
	reqHeader.Set(HeaderTSignOpenAppID, c.appid)
	reqHeader.Set(HeaderTSignOpenAuthMode, AuthModeSign)
	reqHeader.Set(HeaderTSignOpenCaTimestamp, strconv.FormatInt(time.Now().UnixMilli(), 10))
	reqHeader.Set(HeaderTSignOpenCaSignature, NewSigner(http.MethodPost, path, WithSignContMD5(contentMD5), WithSignContType(ContentJSON)).Do(c.secret))

	log.SetReqHeader(reqHeader)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, body, HeaderToHttpOption(reqHeader)...)
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

	reqHeader.Set(HeaderContentType, ContentStream)
	reqHeader.Set(HeaderContentMD5, base64.StdEncoding.EncodeToString(h.Sum(nil)))

	log.SetReqHeader(reqHeader)

	// 文件指针移动到头部
	if _, err := reader.Seek(0, 0); err != nil {
		return err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(), HeaderToHttpOption(reqHeader)...)
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

// PutStreamFromFile 通过文件上传文件流
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

	reqHeader.Set(HeaderContentType, ContentStream)
	reqHeader.Set(HeaderContentMD5, base64.StdEncoding.EncodeToString(h.Sum(nil)))

	log.SetReqHeader(reqHeader)

	// 文件指针移动到头部
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 20<<10)) // 20kb
	if _, err := io.Copy(buf, f); err != nil {
		return err
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPut, uploadURL, buf.Bytes(), HeaderToHttpOption(reqHeader)...)
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
	appid := header.Get(HeaderTSignOpenAppID)
	timestamp := header.Get(HeaderTSignOpenTimestamp)
	sign := header.Get(HeaderTSignOpenSignature)

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

// Option 自定义设置项
type Option func(c *Client)

// WithClient 设置自定义 HTTP Client
func WithClient(cli *http.Client) Option {
	return func(c *Client) {
		c.httpCli = NewHTTPClient(cli)
	}
}

// WithLogger 设置日志记录
func WithLogger(f func(ctx context.Context, data map[string]string)) Option {
	return func(c *Client) {
		c.logger = f
	}
}

// NewClient 返回E签宝客户端
func NewClient(appid, secret string, options ...Option) *Client {
	c := &Client{
		host:    "https://openapi.esign.cn",
		appid:   appid,
		secret:  secret,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}

// NewSandbox 返回E签宝「沙箱环境」客户端
func NewSandbox(appid, secret string, options ...Option) *Client {
	c := &Client{
		host:    "https://smlopenapi.esign.cn",
		appid:   appid,
		secret:  secret,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}
