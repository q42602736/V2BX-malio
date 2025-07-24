package panel

import (
	"github.com/InazumaV/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	Token            string
	NodeType         string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
	sspanelClient    *SSPanelClient
}

func New(c *conf.ApiConfig) (*Client, error) {
	// Default to SSPanel adapter (since this version is specifically for SSPanel)
	return NewSSPanelClient(c)
}

// NewSSPanelClient creates a client that implements the Client interface for SSPanel
func NewSSPanelClient(c *conf.ApiConfig) (*Client, error) {
	sspanelClient, err := NewSSPanel(c)
	if err != nil {
		return nil, err
	}

	// Create a wrapper that implements the original Client interface
	return &Client{
		client:        sspanelClient.client,
		Token:         sspanelClient.Token,
		APIHost:       sspanelClient.APIHost,
		NodeType:      sspanelClient.NodeType,
		NodeId:        sspanelClient.NodeId,
		UserList:      sspanelClient.UserList,
		AliveMap:      sspanelClient.AliveMap,
		sspanelClient: sspanelClient,
	}, nil
}

// ReportNodeStatus reports node status to the panel
func (c *Client) ReportNodeStatus(nodeStatus *NodeStatus) error {
	return c.sspanelClient.ReportNodeStatus(nodeStatus)
}
