package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/InazumaV/V2bX/conf"
	"github.com/go-resty/resty/v2"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
)

// SSPanelClient is the client for SSPanel-UIM API
type SSPanelClient struct {
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
}

// SSPanelNodeResponse represents SSPanel node info response
type SSPanelNodeResponse struct {
	Ret  int             `json:"ret"`
	Data SSPanelNodeData `json:"data"`
}

type SSPanelNodeData struct {
	NodeGroup      int     `json:"node_group"`
	NodeClass      int     `json:"node_class"`
	NodeSpeedLimit int     `json:"node_speedlimit"`
	TrafficRate    float64 `json:"traffic_rate"`
	MuOnly         int     `json:"mu_only"`
	Sort           int     `json:"sort"`
	Server         string  `json:"server"`
	Type           string  `json:"type"`
	Online         int     `json:"online"`
}

// SSPanelUserResponse represents SSPanel user list response
type SSPanelUserResponse struct {
	Ret  int               `json:"ret"`
	Data []SSPanelUserData `json:"data"`
}

type SSPanelUserData struct {
	Id             int    `json:"id"`
	Email          string `json:"email"`
	Passwd         string `json:"passwd"`
	Port           int    `json:"port"`
	Method         string `json:"method"`
	Obfs           string `json:"obfs"`
	ObfsParam      string `json:"obfs_param"`
	Protocol       string `json:"protocol"`
	ProtocolParam  string `json:"protocol_param"`
	ForbiddenIp    string `json:"forbidden_ip"`
	ForbiddenPort  string `json:"forbidden_port"`
	NodeSpeedLimit int    `json:"node_speedlimit"`
	DisconnectIp   string `json:"disconnect_ip"`
	IsMultiUser    int    `json:"is_multi_user"`
	U              int64  `json:"u"`
	D              int64  `json:"d"`
	NodeConnector  int    `json:"node_connector"`
	Sort           int    `json:"sort"`
	Uuid           string `json:"uuid"`
	Sha224Uuid     string `json:"sha224uuid"`
}

// NewSSPanel creates a new SSPanel client
func NewSSPanel(c *conf.ApiConfig) (*SSPanelClient, error) {
	client := resty.New()
	client.SetRetryCount(3)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)

	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case "v2ray":
		c.NodeType = "vmess"
	case
		"vmess",
		"trojan",
		"shadowsocks",
		"hysteria",
		"hysteria2",
		"tuic",
		"anytls",
		"vless":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	return &SSPanelClient{
		client:   client,
		Token:    c.Key,
		APIHost:  c.APIHost,
		NodeType: c.NodeType,
		NodeId:   c.NodeID,
		UserList: &UserListBody{},
		AliveMap: &AliveMap{},
	}, nil
}

// GetNodeInfo gets node configuration from SSPanel
func (c *SSPanelClient) GetNodeInfo() (node *NodeInfo, err error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeId)
	logrus.Debugf("请求节点配置: %s%s", c.APIHost, path)

	r, err := c.client.
		R().
		SetQueryParam("key", c.Token).
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if r.StatusCode() == 304 {
		logrus.Infof("节点配置未变更 (304)")
		return nil, nil
	}

	logrus.Debugf("收到节点配置响应，状态码: %d", r.StatusCode())
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}

	// Parse SSPanel response
	var sspanelResp SSPanelNodeResponse
	if err = json.Unmarshal(r.Body(), &sspanelResp); err != nil {
		logrus.Errorf("解析SSPanel节点响应失败: %s", err)
		logrus.Debugf("原始响应内容: %s", string(r.Body()))
		return nil, fmt.Errorf("decode sspanel node response error: %s", err)
	}

	logrus.Debugf("SSPanel节点响应: ret=%d", sspanelResp.Ret)
	logrus.Debugf("完整节点响应: %+v", sspanelResp)

	if sspanelResp.Ret != 1 {
		logrus.Errorf("SSPanel节点响应失败: ret=%d", sspanelResp.Ret)
		return nil, fmt.Errorf("sspanel node response error: ret=%d", sspanelResp.Ret)
	}

	// Convert SSPanel format to V2bX format
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}

	// Parse server configuration based on sort type
	logrus.Debugf("解析服务器配置: sort=%d, server=%s", sspanelResp.Data.Sort, sspanelResp.Data.Server)

	serverParts := strings.Split(sspanelResp.Data.Server, ";")
	if len(serverParts) == 0 {
		return nil, fmt.Errorf("invalid server configuration: %s", sspanelResp.Data.Server)
	}

	serverHost := serverParts[0]
	serverParams := make(map[string]string)

	if len(serverParts) > 1 {
		// 支持两种分隔符：& (新格式) 和 | (VMess传统格式)
		var params []string
		if strings.Contains(serverParts[1], "&") {
			params = strings.Split(serverParts[1], "&")
		} else {
			params = strings.Split(serverParts[1], "|")
		}
		for _, param := range params {
			kv := strings.Split(param, "=")
			if len(kv) == 2 {
				serverParams[kv[0]] = kv[1]
				logrus.Debugf("解析参数: %s = %s", kv[0], kv[1])
			}
		}
	}

	logrus.Debugf("解析到 %d 个服务器参数", len(serverParams))
	logrus.Debugf("完整参数列表: %+v", serverParams)

	// Create node configuration based on sort type
	switch sspanelResp.Data.Sort {
	case 15, 16: // VLESS
		node = c.createVlessNode(node, serverHost, serverParams, sspanelResp.Data.Sort)
	case 17: // Hysteria2
		node = c.createHy2Node(node, serverHost, serverParams)
	case 18: // AnyTLS
		node = c.createAnyTlsNode(node, serverHost, serverParams)
	case 14: // Trojan
		node = c.createTrojanNode(node, serverHost, serverParams)
	case 11, 12: // V2Ray
		node = c.createVmessNodeFromConfig(node, sspanelResp.Data.Server)
	default:
		return nil, fmt.Errorf("unsupported node sort: %d", sspanelResp.Data.Sort)
	}

	// Set default intervals
	node.PushInterval = 60 * time.Second
	node.PullInterval = 60 * time.Second

	// Set Common field (required for sing-box core)
	var commonNode *CommonNode
	switch sspanelResp.Data.Sort {
	case 15, 16: // VLESS
		if node.VAllss != nil {
			commonNode = &node.VAllss.CommonNode
		}
	case 17: // Hysteria2
		if node.Hysteria2 != nil {
			commonNode = &node.Hysteria2.CommonNode
		}
	case 18: // AnyTLS
		if node.AnyTls != nil {
			commonNode = &node.AnyTls.CommonNode
		}
	case 14: // Trojan
		if node.Trojan != nil {
			commonNode = &node.Trojan.CommonNode
		}
	case 11, 12: // V2Ray
		if node.VAllss != nil {
			commonNode = &node.VAllss.CommonNode
		}
	}

	// Ensure we have a valid common node
	if commonNode == nil {
		return nil, fmt.Errorf("failed to create common node for sort type: %d", sspanelResp.Data.Sort)
	}
	node.Common = commonNode

	return node, nil
}

// createVlessNode creates VLESS node configuration
func (c *SSPanelClient) createVlessNode(node *NodeInfo, host string, params map[string]string, sort int) *NodeInfo {
	port, _ := strconv.Atoi(params["port"])
	if port == 0 {
		port = 443
	}

	vlessNode := &VAllssNode{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
		Network: "tcp",
		Flow:    params["flow"],
	}

	// Set security type
	if sort == 16 {
		if params["security"] != "reality" {
			logrus.Warnf("节点类型为16但security不是reality: '%s'", params["security"])
		}

		vlessNode.Tls = Reality

		serverName := params["serverName"]
		if serverName == "" {
			serverName = "www.microsoft.com"
			logrus.Warnf("serverName为空，使用默认值: %s", serverName)
		}

		dest := params["dest"]
		if dest == "" {
			dest = serverName
		}
		
		destParts := strings.Split(dest, ":")
		destHost := destParts[0]
		destPort := "443"
		if len(destParts) > 1 {
			destPort = destParts[1]
		}

		privateKey := params["privateKey"]
		if privateKey == "" {
			logrus.Errorf("privateKey为空，Reality将无法工作")
		}

		shortId := params["shortId"]

		vlessNode.TlsSettings = TlsSettings{
			ServerName: serverName,
			Dest:       destHost,
			ServerPort: destPort,
			PrivateKey: privateKey,
			ShortId:    shortId,
		}
		logrus.Infof("Reality: serverName=%s, dest=%s, port=%s", serverName, destHost, destPort)
		node.Security = Reality
	} else {
		vlessNode.Tls = None
		node.Security = None
	}

	node.VAllss = vlessNode
	return node
}

// createTrojanNode creates Trojan node configuration
func (c *SSPanelClient) createTrojanNode(node *NodeInfo, host string, params map[string]string) *NodeInfo {
	port, _ := strconv.Atoi(params["port"])
	if port == 0 {
		port = 443
	}

	trojanNode := &TrojanNode{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
		Network: "tcp",
	}

	node.Trojan = trojanNode
	node.Security = Tls
	return node
}

// createVmessNode creates VMess node configuration
func (c *SSPanelClient) createVmessNode(node *NodeInfo, host string, params map[string]string) *NodeInfo {
	port, _ := strconv.Atoi(params["port"])
	if port == 0 {
		port = 443
	}

	network := params["net"]
	if network == "" {
		network = "tcp"
	}

	vmessNode := &VAllssNode{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
		Network: network,
		Tls:     0,
	}

	if params["tls"] == "tls" {
		vmessNode.Tls = Tls
		node.Security = Tls
	} else {
		node.Security = None
	}

	// Set network settings
	networkSettings := make(map[string]interface{})
	switch params["net"] {
	case "ws":
		networkSettings["path"] = params["path"]
		networkSettings["headers"] = map[string]string{
			"Host": params["host"],
		}
	case "grpc":
		networkSettings["service_name"] = params["serviceName"]
	case "h2":
		networkSettings["path"] = params["path"]
		networkSettings["host"] = []string{params["host"]}
	}

	if len(networkSettings) > 0 {
		networkSettingsJson, _ := json.Marshal(networkSettings)
		vmessNode.NetworkSettings = networkSettingsJson
	}

	node.VAllss = vmessNode
	return node
}

// createVmessNodeFromConfig creates VMess node configuration from traditional format
// Format: host;port;alterId;network;type;params
func (c *SSPanelClient) createVmessNodeFromConfig(node *NodeInfo, serverConfig string) *NodeInfo {
	logrus.Infof("解析VMess配置: %s", serverConfig)

	// Split by semicolon for traditional VMess format
	parts := strings.Split(serverConfig, ";")
	if len(parts) < 4 {
		logrus.Errorf("VMess配置格式错误，期望至少4个部分，实际: %d", len(parts))
		return node
	}

	// Parse basic configuration
	host := parts[0]
	port, _ := strconv.Atoi(parts[1])
	if port == 0 {
		port = 443
	}
	alterId, _ := strconv.Atoi(parts[2])
	network := parts[3]
	// parts[4] is type, usually empty

	logrus.Infof("VMess基础配置: host=%s, port=%d, alterId=%d, network=%s", host, port, alterId, network)

	// Parse parameters if present
	params := make(map[string]string)
	if len(parts) > 5 && parts[5] != "" {
		logrus.Infof("解析VMess参数: %s", parts[5])
		// Support both | and & separators
		var paramPairs []string
		if strings.Contains(parts[5], "&") {
			paramPairs = strings.Split(parts[5], "&")
		} else {
			paramPairs = strings.Split(parts[5], "|")
		}

		for _, pair := range paramPairs {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
				logrus.Debugf("VMess参数: %s = %s", kv[0], kv[1])
			}
		}
	}

	// Create VMess node
	vmessNode := &VAllssNode{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
		Network: network,
		Tls:     0,
	}

	logrus.Infof("创建VMess节点: host=%s, port=%d, network=%s", host, port, network)

	// Set TLS
	if params["tls"] == "tls" {
		vmessNode.Tls = Tls
		node.Security = Tls
		logrus.Infof("启用TLS (通过tls参数)")
	} else {
		node.Security = None
		logrus.Infof("未启用TLS")
	}

	// Set network-specific settings
	networkSettings := make(map[string]interface{})
	switch network {
	case "ws":
		path := params["path"]
		if path == "" {
			path = "/"
		}
		networkSettings["path"] = path

		// Set host header - use host param if available, otherwise use server host
		hostHeader := params["host"]
		if hostHeader == "" {
			hostHeader = host
		}
		networkSettings["headers"] = map[string]string{"Host": hostHeader}

		logrus.Infof("WebSocket配置: path=%s, host=%s", path, hostHeader)
	case "grpc":
		serviceName := params["serviceName"]
		if serviceName == "" {
			serviceName = "GunService"
		}
		networkSettings["service_name"] = serviceName
	case "h2":
		path := params["path"]
		if path == "" {
			path = "/"
		}
		networkSettings["path"] = path
		hostHeader := params["host"]
		if hostHeader == "" {
			hostHeader = host
		}
		networkSettings["host"] = []string{hostHeader}
	}

	if len(networkSettings) > 0 {
		networkSettingsJson, _ := json.Marshal(networkSettings)
		vmessNode.NetworkSettings = networkSettingsJson
		logrus.Infof("网络设置: %s", string(networkSettingsJson))
	}

	node.VAllss = vmessNode

	// 最终调试信息
	logrus.Infof("VMess节点创建完成: host=%s, port=%d, network=%s, tls=%d",
		vmessNode.Host, vmessNode.ServerPort, vmessNode.Network, vmessNode.Tls)

	return node
}

// GetUserList gets user list from SSPanel
func (c *SSPanelClient) GetUserList() ([]UserInfo, error) {
	path := "/mod_mu/users"
	r, err := c.client.R().
		SetQueryParam("key", c.Token).
		SetQueryParam("node_id", strconv.Itoa(c.NodeId)).
		SetHeader("If-None-Match", c.userEtag).
		ForceContentType("application/json").
		Get(path)

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	var sspanelResp SSPanelUserResponse
	if err = json.Unmarshal(r.Body(), &sspanelResp); err != nil {
		return nil, fmt.Errorf("decode sspanel user response error: %s", err)
	}

	if sspanelResp.Ret != 1 {
		return nil, fmt.Errorf("sspanel user response error: ret=%d", sspanelResp.Ret)
	}

	// Convert SSPanel users to V2bX format
	users := make([]UserInfo, len(sspanelResp.Data))
	for i, sspanelUser := range sspanelResp.Data {
		users[i] = UserInfo{
			Id:          sspanelUser.Id,
			Uuid:        sspanelUser.Uuid,
			SpeedLimit:  sspanelUser.NodeSpeedLimit,
			DeviceLimit: sspanelUser.NodeConnector,
		}
	}

	c.userEtag = r.Header().Get("ETag")
	return users, nil
}

// GetUserAlive gets alive user count from SSPanel
func (c *SSPanelClient) GetUserAlive() (map[int]int, error) {
	// SSPanel doesn't have a direct alive count API, return empty map
	c.AliveMap = &AliveMap{
		Alive: make(map[int]int),
	}
	return c.AliveMap.Alive, nil
}

// ReportUserTraffic reports user traffic to SSPanel
func (c *SSPanelClient) ReportUserTraffic(userTraffic []UserTraffic) error {
	if len(userTraffic) == 0 {
		return nil
	}

	// 计算上报前的流量统计
	totalUpload := int64(0)
	totalDownload := int64(0)

	// Convert to SSPanel format - SSPanel expects data parameter with array of objects
	trafficData := make([]map[string]interface{}, 0, len(userTraffic))
	for _, traffic := range userTraffic {
		totalUpload += traffic.Upload
		totalDownload += traffic.Download

		trafficData = append(trafficData, map[string]interface{}{
			"user_id": traffic.UID,
			"u":       traffic.Upload,
			"d":       traffic.Download,
		})

		// 每个用户的详细流量信息
		logrus.WithFields(logrus.Fields{
			"user_id":        traffic.UID,
			"upload_bytes":   traffic.Upload,
			"download_bytes": traffic.Download,
			"upload_mb":      float64(traffic.Upload) / 1024 / 1024,
			"download_mb":    float64(traffic.Download) / 1024 / 1024,
			"total_mb":       float64(traffic.Upload+traffic.Download) / 1024 / 1024,
		}).Debug("准备上报用户流量")
	}

	// Wrap in data parameter as expected by SSPanel
	requestData := map[string]interface{}{
		"data": trafficData,
	}

	// 上报前的最终统计信息
	logrus.WithFields(logrus.Fields{
		"node_id":              c.NodeId,
		"user_count":           len(userTraffic),
		"total_upload_bytes":   totalUpload,
		"total_download_bytes": totalDownload,
		"total_upload_mb":      float64(totalUpload) / 1024 / 1024,
		"total_download_mb":    float64(totalDownload) / 1024 / 1024,
		"total_traffic_mb":     float64(totalUpload+totalDownload) / 1024 / 1024,
	}).Info("向SSPanel上报流量数据")

	path := "/mod_mu/users/traffic"
	r, err := c.client.R().
		SetQueryParam("key", c.Token).
		SetQueryParam("node_id", strconv.Itoa(c.NodeId)).
		SetBody(requestData).
		ForceContentType("application/json").
		Post(path)

	err = c.checkResponse(r, path, err)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node_id":     c.NodeId,
			"error":       err.Error(),
			"status_code": r.StatusCode(),
		}).Error("流量上报失败")
		return err
	}

	logrus.WithFields(logrus.Fields{
		"node_id":          c.NodeId,
		"status_code":      r.StatusCode(),
		"user_count":       len(userTraffic),
		"total_traffic_mb": float64(totalUpload+totalDownload) / 1024 / 1024,
	}).Info("流量上报成功")

	return nil
}

// ReportNodeOnlineUsers reports online users to SSPanel
func (c *SSPanelClient) ReportNodeOnlineUsers(data *map[int][]string) error {
	logrus.WithFields(logrus.Fields{
		"node_id":    c.NodeId,
		"data_count": len(*data),
	}).Debug("开始上报在线设备")

	if data == nil || len(*data) == 0 {
		logrus.Debug("在线设备数据为空，跳过上报")
		return nil
	}

	// Convert to SSPanel format: [{"ip": "ip1", "user_id": 1}]
	aliveData := make([]map[string]interface{}, 0)
	for uid, ips := range *data {
		logrus.WithFields(logrus.Fields{
			"uid":      uid,
			"ip_count": len(ips),
			"ips":      ips,
		}).Debug("处理用户在线IP")
		
		for _, ip := range ips {
			aliveData = append(aliveData, map[string]interface{}{
				"ip":      ip,
				"user_id": uid,
			})
		}
	}

	logrus.WithFields(logrus.Fields{
		"node_id":        c.NodeId,
		"total_records":  len(aliveData),
		"formatted_data": aliveData,
	}).Info("准备上报在线设备数据")

	// Wrap data in PostData structure like XrayR does
	postData := map[string]interface{}{
		"data": aliveData,
	}

	path := "/mod_mu/users/aliveip"
	r, err := c.client.R().
		SetQueryParam("key", c.Token).
		SetQueryParam("node_id", strconv.Itoa(c.NodeId)).
		SetBody(postData).
		ForceContentType("application/json").
		Post(path)

	logrus.WithFields(logrus.Fields{
		"node_id":     c.NodeId,
		"status_code": r.StatusCode(),
		"response":    r.String(),
		"error":       err,
	}).Debug("在线设备上报API响应")

	err = c.checkResponse(r, path, err)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node_id": c.NodeId,
			"error":   err.Error(),
		}).Error("在线设备上报失败")
		return err
	}

	logrus.WithFields(logrus.Fields{
		"node_id":       c.NodeId,
		"total_records": len(aliveData),
	}).Info("在线设备上报成功")

	return nil
}

// checkResponse checks the response status and returns error if needed
func (c *SSPanelClient) checkResponse(r *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s error: %s", path, err)
	}

	if r.StatusCode() >= 400 {
		return fmt.Errorf("request %s failed with status %d: %s", path, r.StatusCode(), string(r.Body()))
	}

	return nil
}

// createHy2Node creates Hysteria2 node configuration
func (c *SSPanelClient) createHy2Node(node *NodeInfo, host string, params map[string]string) *NodeInfo {
	logrus.Infof("创建Hysteria2节点: host=%s", host)

	port, _ := strconv.Atoi(params["port"])
	if port == 0 {
		port = 443
	}
	logrus.Infof("Hysteria2节点端口: %d", port)

	// Parse bandwidth parameters
	upMbps, _ := strconv.Atoi(params["up_mbps"])
	if upMbps == 0 {
		upMbps = 100 // Default 100 Mbps
	}
	downMbps, _ := strconv.Atoi(params["down_mbps"])
	if downMbps == 0 {
		downMbps = 100 // Default 100 Mbps
	}

	// Parse obfuscation parameters
	obfsType := params["obfs"]
	if obfsType == "" {
		obfsType = "plain"
	}
	obfsPassword := params["obfs_password"]

	// Parse ignore client bandwidth
	ignoreClientBandwidth := params["ignore_client_bandwidth"] == "1" || params["ignore_client_bandwidth"] == "true"

	hy2Node := &Hysteria2Node{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
		UpMbps:                  upMbps,
		DownMbps:                downMbps,
		ObfsType:                obfsType,
		ObfsPassword:            obfsPassword,
		Ignore_Client_Bandwidth: ignoreClientBandwidth,
	}

	// Parse allow insecure for client config
	allowInsecure := params["allow_insecure"] == "1" || params["allow_insecure"] == "true"

	logrus.Infof("Hysteria2配置: upMbps=%d, downMbps=%d, obfs=%s, ignoreClientBandwidth=%t, allowInsecure=%t",
		upMbps, downMbps, obfsType, ignoreClientBandwidth, allowInsecure)

	node.Hysteria2 = hy2Node
	node.Security = Tls // HY2 requires TLS
	return node
}

// SystemLoad represents the system load data for reporting
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// NodeStatus represents the node status information
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

// ReportNodeStatus reports the node status to the panel
func (c *SSPanelClient) ReportNodeStatus(nodeStatus *NodeStatus) error {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeId)

	systemLoad := SystemLoad{
		Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.Mem/100, nodeStatus.Disk/100),
	}

	// 详细的上报前调试信息
	logrus.WithFields(logrus.Fields{
		"node_id":     c.NodeId,
		"api_host":    c.APIHost,
		"path":        path,
		"load_string": systemLoad.Load,
		"uptime":      systemLoad.Uptime,
		"cpu_raw":     nodeStatus.CPU,
		"mem_raw":     nodeStatus.Mem,
		"disk_raw":    nodeStatus.Disk,
	}).Debug("开始调用面板API上报节点负载")

	res, err := c.client.R().
		SetQueryParam("key", c.Token).
		SetFormData(map[string]string{
			"load":   systemLoad.Load,
			"uptime": systemLoad.Uptime,
		}).
		Post(c.APIHost + path)

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"node_id":  c.NodeId,
			"api_host": c.APIHost,
			"path":     path,
			"error":    err,
		}).Error("调用面板API失败")
		return fmt.Errorf("failed to report node status: %w", err)
	}

	if res.StatusCode() != 200 {
		logrus.WithFields(logrus.Fields{
			"node_id":     c.NodeId,
			"api_host":    c.APIHost,
			"path":        path,
			"status_code": res.StatusCode(),
			"response":    res.String(),
		}).Error("面板API返回错误状态码")
		return fmt.Errorf("failed to report node status, status code: %d, body: %s", res.StatusCode(), res.String())
	}

	// 成功上报的详细信息
	logrus.WithFields(logrus.Fields{
		"node_id":      c.NodeId,
		"api_host":     c.APIHost,
		"path":         path,
		"status_code":  res.StatusCode(),
		"response":     res.String(),
		"load_string":  systemLoad.Load,
		"uptime":       systemLoad.Uptime,
		"cpu_percent":  nodeStatus.CPU,
		"mem_percent":  nodeStatus.Mem,
		"disk_percent": nodeStatus.Disk,
	}).Debug("节点负载上报API调用成功")

	return nil
}

// createAnyTlsNode creates AnyTLS node configuration
func (c *SSPanelClient) createAnyTlsNode(node *NodeInfo, host string, params map[string]string) *NodeInfo {
	logrus.Infof("创建AnyTLS节点: host=%s", host)
	logrus.Infof("接收到的所有参数: %+v", params)

	port, _ := strconv.Atoi(params["port"])
	if port == 0 {
		port = 443
	}
	logrus.Infof("AnyTLS节点端口: %d", port)

	anyTlsNode := &AnyTlsNode{
		CommonNode: CommonNode{
			Host:       host,
			ServerPort: port,
			BaseConfig: &BaseConfig{
				PushInterval: "60s",
				PullInterval: "60s",
			},
		},
	}

	// Parse padding_scheme if present
	if paddingSchemeStr := params["padding_scheme"]; paddingSchemeStr != "" {
		logrus.Infof("原始padding_scheme字符串(URL编码): '%s'", paddingSchemeStr)
		
		// URL decode the padding_scheme string first
		decodedStr, err := url.QueryUnescape(paddingSchemeStr)
		if err != nil {
			logrus.Errorf("URL解码padding_scheme失败: %s", err)
			decodedStr = paddingSchemeStr // fallback to original
		}
		logrus.Infof("URL解码后的padding_scheme: '%s'", decodedStr)
		
		// padding_scheme is a JSON array string like: ["stop=8","0=30-30","1=100-400"]
		var paddingScheme []string
		if err := json.Unmarshal([]byte(decodedStr), &paddingScheme); err != nil {
			logrus.Errorf("解析padding_scheme失败: %s", err)
			logrus.Errorf("尝试解析的字符串: '%s'", decodedStr)
			// Use default padding scheme if parsing fails
			paddingScheme = []string{
				"stop=8",
				"0=30-30",
				"1=100-400",
				"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
				"3=9-9,500-1000",
				"4=500-1000",
				"5=500-1000",
				"6=500-1000",
				"7=500-1000",
			}
			logrus.Warnf("使用默认padding_scheme")
		}
		anyTlsNode.PaddingScheme = paddingScheme
		logrus.Infof("最终AnyTLS padding_scheme: %v", paddingScheme)
		logrus.Infof("padding_scheme数组长度: %d", len(paddingScheme))
		for i, scheme := range paddingScheme {
			logrus.Infof("  [%d]: %s", i, scheme)
		}
	} else {
		// Use default padding scheme
		anyTlsNode.PaddingScheme = []string{
			"stop=8",
			"0=30-30",
			"1=100-400",
			"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
			"3=9-9,500-1000",
			"4=500-1000",
			"5=500-1000",
			"6=500-1000",
			"7=500-1000",
		}
		logrus.Infof("padding_scheme参数为空，使用默认值: %v", anyTlsNode.PaddingScheme)
	}

	// Parse server_name (SNI)
	serverName := params["server_name"]
	if serverName == "" {
		serverName = host
	}
	anyTlsNode.ServerName = serverName
	logrus.Infof("AnyTLS server_name: %s", serverName)

	node.AnyTls = anyTlsNode
	node.Security = Tls // AnyTLS requires TLS
	
	logrus.Infof("AnyTLS节点创建完成: host=%s, port=%d, server_name=%s",
		anyTlsNode.Host, anyTlsNode.ServerPort, anyTlsNode.ServerName)
	logrus.Infof("最终节点配置: %+v", anyTlsNode)
	
	return node
}
