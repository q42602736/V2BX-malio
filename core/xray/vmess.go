package xray

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
)

// isValidUUID 检查字符串是否为有效的UUID格式
func isValidUUID(uuid string) bool {
	// UUID格式：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidRegex.MatchString(uuid)
}

// convertToUUID 将任意字符串转换为有效的UUID格式
func convertToUUID(input string) string {
	if isValidUUID(input) {
		return input
	}

	// 如果不是有效UUID，使用MD5哈希生成UUID格式
	hash := md5.Sum([]byte(input))
	hashStr := fmt.Sprintf("%x", hash)

	// 将32位哈希转换为UUID格式：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	uuid := fmt.Sprintf("%s-%s-%s-%s-%s",
		hashStr[0:8],
		hashStr[8:12],
		hashStr[12:16],
		hashStr[16:20],
		hashStr[20:32])

	return strings.ToLower(uuid)
}

func buildVmessUsers(tag string, userInfo []panel.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i, user := range userInfo {
		users[i] = buildVmessUser(tag, &user)
	}
	return users
}

func buildVmessUser(tag string, userInfo *panel.UserInfo) (user *protocol.User) {
	// 转换UUID为有效格式
	validUUID := convertToUUID(userInfo.Uuid)

	vmessAccount := &conf.VMessAccount{
		ID:       validUUID,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid), // Uid: InboundTag|email
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildVlessUsers(tag string, userInfo []panel.UserInfo, flow string) (users []*protocol.User) {
	users = make([]*protocol.User, len(userInfo))
	for i := range userInfo {
		users[i] = buildVlessUser(tag, &(userInfo)[i], flow)
	}
	return users
}

func buildVlessUser(tag string, userInfo *panel.UserInfo, flow string) (user *protocol.User) {
	// 转换UUID为有效格式
	validUUID := convertToUUID(userInfo.Uuid)

	vlessAccount := &vless.Account{
		Id: validUUID,
	}
	vlessAccount.Flow = flow
	return &protocol.User{
		Level:   0,
		Email:   format.UserTag(tag, userInfo.Uuid),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}
