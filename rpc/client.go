package rpc

import (
	"github.com/BatuhanK/go-web3/rpc/transport"
)

type Client struct {
	transport transport.Transport
	addr      string
}

func NewClient(addr, proxy string, headers map[string]string) (*Client, error) {
	c := &Client{
		addr: addr,
	}

	t, err := transport.NewTransport(addr, proxy, headers)
	if err != nil {
		return nil, err
	}
	c.transport = t
	return c, nil
}
func NewClientWithHeaders(addr string, headers map[string]string) (*Client, error) {
	c := &Client{
		addr: addr,
	}

	t, err := transport.NewTransportWithHeaders(addr, headers)
	if err != nil {
		return nil, err
	}
	c.transport = t
	return c, nil
}

func (c *Client) Close() error {
	return c.transport.Close()
}

func (c *Client) Call(method string, out interface{}, params ...interface{}) error {
	return c.transport.Call(method, out, params...)
}
