package codec

import (
	"sync"

	"github.com/luyu6056/cache"
	"github.com/luyu6056/tls"
)

//ctx不带服务类型应用，应该作为一个通用的ctx

type Context struct { //循环的Context
	In        *tls.MsgBuffer
	In2       *tls.MsgBuffer
	Log       []*Err_log
	Sql_build interface{}
	Buf       *tls.MsgBuffer //辅助out用于序列化
	Conn      *ClientConn
	Conn_m    *sync.Map //rpc用
	//Transaction *mysql.Transaction //sql的事务
}

var ClientId int32

type ClientConn struct {
	Id          int32 //自增的ClientId
	ClientFd    [4]byte
	BeginTime   int64 //连接开始时间
	Session     *cache.Hashvalue
	IP          string
	UserAgent   string
	IsMobile    bool
	Output_data func(*tls.MsgBuffer)
}

var ServerHand func(*Context)

type Err_log struct {
	Err       string
	Err_func  string
	Err_param string
}

/**
 * 输出
 *
 **/
type OutMsg interface {
	WRITE(buf *tls.MsgBuffer)
}

func (c *Context) Output_data(msg OutMsg) {
	msg.WRITE(c.Buf)
	c.Conn.Output_data(c.Buf)
}
