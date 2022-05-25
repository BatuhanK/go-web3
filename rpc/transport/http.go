package transport

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BatuhanK/go-web3/rpc/codec"
	"github.com/valyala/fasthttp"
)

var (
	dialTimeout = time.Minute
)

type HTTP struct {
	addr    string
	proxy   string
	client  *fasthttp.Client
	headers map[string]string
}

func newHTTP(addr string, proxy string) *HTTP {
	if len(proxy) == 0 {
		return &HTTP{
			addr: addr,
			client: &fasthttp.Client{
				Dial: func(addr string) (net.Conn, error) {
					return fasthttp.DialTimeout(addr, dialTimeout)
				},
			},
		}
	}

	return &HTTP{
		addr:  addr,
		proxy: proxy,
		client: &fasthttp.Client{
			Dial: httpProxyDialer(proxy, dialTimeout),
		},
	}
}

func newHTTPWithHeaders(addr string, headers map[string]string) *HTTP {
	return &HTTP{
		addr: addr,
		client: &fasthttp.Client{
			Dial: func(addr string) (net.Conn, error) {
				return fasthttp.DialTimeout(addr, dialTimeout)
			},
		},
		headers: headers,
	}

}

func (h *HTTP) Close() error {
	return nil
}

func (h *HTTP) Call(method string, out interface{}, params ...interface{}) error {
	request := codec.Request{
		Method:  method,
		Version: "2.0",
	}
	if len(params) > 0 {
		data, err := json.Marshal(params)
		if err != nil {
			return err
		}
		request.Params = data
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req := fasthttp.AcquireRequest()
	res := fasthttp.AcquireResponse()

	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(res)

	req.SetRequestURI(h.addr)
	if len(h.headers) != 0 {
		for k, v := range h.headers {
			req.Header.Add(k, v)
		}
	}
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/json")
	req.SetBody(raw)

	if err := h.client.Do(req, res); err != nil {
		return err
	}

	var response codec.Response
	if err := json.Unmarshal(res.Body(), &response); err != nil {
		return err
	}
	if response.Error != nil {
		return response.Error
	}

	if err := json.Unmarshal(response.Result, out); err != nil {
		return err
	}
	return nil
}

func httpProxyDialer(proxy string, timeout time.Duration) fasthttp.DialFunc {
	if strings.Contains(proxy, "http://") {
		proxy = strings.TrimPrefix(proxy, "http://")
	}
	if strings.Contains(proxy, "https://") {
		proxy = strings.TrimPrefix(proxy, "https://")
	}
	return func(addr string) (net.Conn, error) {
		var auth string
		if strings.Contains(proxy, "@") {
			split := strings.Split(proxy, "@")
			auth = base64.StdEncoding.EncodeToString([]byte(split[0]))
			proxy = split[1]

		}

		conn, err := fasthttp.DialTimeout(proxy, timeout)
		if err != nil {
			return nil, err
		}

		req := "CONNECT " + addr + " HTTP/1.1\r\n"
		if auth != "" {
			req += "Proxy-Authorization: Basic " + auth + "\r\n"
		}
		req += "\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return nil, err
		}

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		res.SkipBody = true

		if err := res.Read(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return nil, err
		}
		if res.Header.StatusCode() != 200 {
			conn.Close()
			return nil, fmt.Errorf("could not connect to proxy")
		}
		return conn, nil
	}
}
