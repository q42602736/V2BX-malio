package node

import (
	"fmt"
	"strconv"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/serverstatus"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	// Get User traffic
	userTraffic := make([]panel.UserTraffic, 0)
	totalUp := int64(0)
	totalDown := int64(0)

	for i := range c.userList {
		up, down := c.server.GetUserTraffic(c.tag, c.userList[i].Uuid, true)
		if up > 0 || down > 0 {
			if c.LimitConfig.EnableDynamicSpeedLimit {
				c.traffic[c.userList[i].Uuid] += up + down
			}
			userTraffic = append(userTraffic, panel.UserTraffic{
				UID:      (c.userList)[i].Id,
				Upload:   up,
				Download: down})

			totalUp += up
			totalDown += down
			log.WithFields(log.Fields{
				"tag":            c.tag,
				"user_id":        (c.userList)[i].Id,
				"uuid":           c.userList[i].Uuid,
				"upload_bytes":   up,
				"download_bytes": down,
				"upload_mb":      float64(up) / 1024 / 1024,
				"download_mb":    float64(down) / 1024 / 1024,
				"total_mb":       float64(up+down) / 1024 / 1024,
			}).Info("用户流量统计")
		}
	}
	if len(userTraffic) > 0 {
		// 上报前的汇总调试信息
		log.WithFields(log.Fields{
			"tag":                  c.tag,
			"user_count":           len(userTraffic),
			"total_upload_bytes":   totalUp,
			"total_download_bytes": totalDown,
			"total_upload_mb":      float64(totalUp) / 1024 / 1024,
			"total_download_mb":    float64(totalDown) / 1024 / 1024,
			"total_traffic_mb":     float64(totalUp+totalDown) / 1024 / 1024,
		}).Info("准备上报流量汇总")

		err = c.apiClient.ReportUserTraffic(userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithFields(log.Fields{
				"tag":              c.tag,
				"user_count":       len(userTraffic),
				"total_traffic_mb": float64(totalUp+totalDown) / 1024 / 1024,
			}).Infof("成功上报 %d 个用户的流量数据", len(userTraffic))
		}
	}

	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if len(*onlineDevice) > 0 {
		// Only report user has traffic > 100kb to allow ping test
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(c.Options.DeviceOnlineMinTraffic*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if err = c.apiClient.ReportNodeOnlineUsers(&data); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(*onlineDevice), len(result))
		}
	}

	// Report node status along with traffic
	log.WithField("tag", c.tag).Debug("开始获取系统负载信息")
	cpu, mem, disk, uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warning("获取系统信息失败，使用默认值")
		// Continue with default values
		cpu, mem, disk, uptime = 0, 0, 0, 0
	} else {
		log.WithFields(log.Fields{
			"tag":        c.tag,
			"cpu_usage":  cpu,
			"mem_usage":  mem,
			"disk_usage": disk,
			"uptime":     uptime,
		}).Debug("成功获取系统负载信息")
	}

	nodeStatus := &panel.NodeStatus{
		CPU:    cpu,
		Mem:    mem,
		Disk:   disk,
		Uptime: uptime,
	}

	// 准备上报负载信息
	log.WithFields(log.Fields{
		"tag":            c.tag,
		"cpu_percent":    cpu,
		"mem_percent":    mem,
		"disk_percent":   disk,
		"uptime_seconds": uptime,
		"load_string":    fmt.Sprintf("%.2f %.2f %.2f", cpu/100, mem/100, disk/100),
	}).Info("准备上报节点负载信息")

	err = c.apiClient.ReportNodeStatus(nodeStatus)
	if err != nil {
		log.WithFields(log.Fields{
			"tag":          c.tag,
			"err":          err,
			"cpu_percent":  cpu,
			"mem_percent":  mem,
			"disk_percent": disk,
		}).Error("节点负载上报失败")
		// Don't return error, continue with traffic report
	} else {
		log.WithFields(log.Fields{
			"tag":          c.tag,
			"cpu_percent":  cpu,
			"mem_percent":  mem,
			"disk_percent": disk,
			"uptime_hours": float64(uptime) / 3600,
		}).Info("节点负载上报成功")
	}

	userTraffic = nil
	return nil
}

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		oldMap[key] = i
	}

	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}
