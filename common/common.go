package common

import "time"

//Client给服务器发送消息
const (
	LOGIN  byte = iota				//Client登录时消息头
	LOGOUT
	P2PTRANS						//Client向服务器发送的协助打洞头
	GETALLUSER
	GETUSER
)

//Server默认监听端口和ip
const SERVER_PORT  =  8848
const SERVER_IP		= "0.0.0.0"

const CLIENT_PORT  = 8900
const CLIENT_IP  = "0.0.0.0"


//发送消息长度
const BUFFSIZE		=  4096

//Client登录时向服务器发送的消息
type StLoginMessage struct {
	UserName  string
}

//Client注销时发送的消息
type StLogoutMessage struct {
	UserName  string
}

//客户节点信息
type StUserListNode struct {
	UserInfo  StLoginMessage
	Ip        string
	Port      int
}

//Server向Client发送的消息
type StServerToClient struct {
	User		StUserListNode
}

//Client打洞握手时的消息
type Handshack struct {
	From     string
	To       string
	Message  string
}

/*********************************************
下面的协议用于客户端之间的通信
 ********************************************/
const (
	P2PMESSAGE	byte	=	iota
	P2PTRANSMSG
	USERCOUNT

	P2PTRANSACK

	//服务器回客户端消息
	USERINFO
	S2PTRANSMSG
	ERRORMSG
)

const P2PSHAKETIMEOUT  = time.Second * 2


//客户端之间的发送消息格式
type StP2PMessage struct {
	IMessageType	int
	Ip				string
	Port			int
}

type STATE  int


//节点之间是否已经p2p直连
const  P2P_MESSAGR_TRANS  = 1
const  P2P_MESSAGT_CONNECT = 2

var HANDSHACK_MESSAGE string = "Handshake"


