package config

import (
	"encoding/json"
	"io/ioutil"
)

const (
	Controller_limit = 50
)

var Server struct {
	Listen               string
	Mysql_ssl_ca         string
	Mysql_ssl_cert       string
	Mysql_ssl_key        string
	Mysql_ssl_ServerName string
	MysqlAddr            string
	Origin               string
}

func init() {
	data, err := ioutil.ReadFile("./config/config.json")
	if err != nil {
		panic(err)
		return
	}
	err = json.Unmarshal(data, &Server)
	if err != nil {
		panic(err)
	}
}

const (
	ResetPasswordExpire = 3 * 60
	ThreadIconNull      = -1
	ThreadStampNull     = -1
	//显示排序相关
	ThreadDisplayDraft   = -4 //草稿
	ThreadDisplayInCheck = -2 //审核
	ThreadDisplayCommon  = 0  //默认
	ThreadDisplayStick1  = 1  //板块置顶
	ThreadDisplayStick2  = 2  //大区置顶
	ThreadDisplayStick3  = 3  //全局置顶
	//发帖操作相关
	ThreadOperateTypeNew   = 0 //新帖子
	ThreadOperateTypeEdit  = 1
	ThreadOperateTypeReply = 2
)
const (
	//帖子类型相关
	ThreadSpecialCommon   = iota
	ThreadSpecialPoll     //投票主题
	ThreadSpecialTrade    //商品主题
	ThreadSpecialReward   //悬赏主题
	ThreadSpecialActivity //活动主题
	ThreadSpecialDebate   //辩论主题
	//
	ThreadStatusOrderDesc     = 4
	ThreadStatusHiddenreplies = 2

	ThreadAttachmentTypeNull = 0
	ThreadAttachmentTypeImg  = 2
)
