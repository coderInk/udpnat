package main

import (
	"MyCode/udpnat/common"
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli"
	"net"
	"os"
	"strconv"
)

var (
	app = cli.NewApp()

	ipFlag = cli.StringFlag{
		Name:	"ip",
		Value:	common.SERVER_IP,
		Usage:	"Server Listen ip",
	}

	portFlag = cli.IntFlag{
		Name:	"port",
		Value:   common.SERVER_PORT,
		Usage:   "listening port",
	}

)

//存放登录用户信息
var userList map[common.StUserListNode]struct{}


type peer struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	writeAddr  *net.UDPAddr
	ReadMsgCh  chan stReadMsg
	WriteMsgCh chan *sendMsg
}

type sendMsg struct {
	contentMsg  []byte
	reply		chan error
}

type stReadMsg struct {
	content   []byte
	length    int
	addr      string
}

func init() {
	app.Name = "updNatServer"
	app.Usage = "upd NAT Server"
	app.Flags = []cli.Flag{
		portFlag,
		ipFlag,
	}

	userList = make(map[common.StUserListNode]struct{})

	app.Action = updServer
}

func main(){
	fmt.Println("udp Server begin to Work...")
	app.Run(os.Args)
	console()
	fmt.Println("main end...")
}

func updServer(ctx *cli.Context) error{
	go listenToConnect(ctx)

	return nil
}

func console() {
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		command := input.Text()
		fmt.Println("command:",command)
	}
}

func listenToConnect(ctx *cli.Context) {
	address := ctx.GlobalString(ipFlag.Name) + ":" + strconv.Itoa(ctx.GlobalInt(portFlag.Name))
    addr, err := net.ResolveUDPAddr("udp",address)
    if err != nil {
    	fmt.Println("listenToConnect		"," ResolveUDPAddr fail,err:",err)
		return
	}

	conn, err := net.ListenUDP("udp",addr)
	if err != nil {
		fmt.Println("listenToConnect		"," ListenUDP fail,err:",err)
		return
	}
	fmt.Println("listen address: ",address)

	go readMsg(conn)
}


func newPeer(conn *net.UDPConn)*peer{
	return &peer{
		conn:conn,
		ReadMsgCh:make(chan stReadMsg),
		WriteMsgCh:make(chan *sendMsg),
	}
}

func readMsg(conn *net.UDPConn){
	defer conn.Close()
		for{
			buff := make([]byte,common.BUFFSIZE)

			nRead, addr, err := conn.ReadFromUDP(buff)
			if err != nil {
				fmt.Println("readMsg		","ReadFromUDP fail,err:",err)
				return
			}

			s := newPeer(conn)

			msg := stReadMsg{
				content:make([]byte,0,len(buff)),
				length:nRead,
				addr:addr.String(),
			}
			msg.content = buff
			s.addr = addr
			s.writeAddr = addr

			go func(msg stReadMsg){
				s.ReadMsgCh <- msg
			}(msg)

			go s.loop()
		}
}

func (s *peer)writeMsg(msg *sendMsg){
	msgBuff := msg.contentMsg
	mReply := msg.reply

	_, err := s.conn.WriteToUDP(msgBuff,s.writeAddr)
	if err != nil {
		fmt.Println("write message fail,err:",err)
		deleteUserFromAddr(s.writeAddr.String())
		return
	}

	mReply <- err
}

func (s *peer)loop(){
	for{
		select {
		case rMsg := <- s.ReadMsgCh:
			msg := rMsg.content
			addr := rMsg.addr
			msgContent := msg[1:rMsg.length]

			switch msg[0] {
			case common.LOGIN:
				go s.handleLogin(msgContent,addr)
			case common.LOGOUT:
				go s.handleLogout(msgContent,addr)
			case common.P2PTRANS:
				go s.handleTrans(msgContent,addr)
			case common.GETALLUSER:
				fmt.Println("loop	","msgContent:",msgContent)
			case common.GETUSER:
				go s.handleGetUset(msgContent,addr)
			}
		case msg := <- s.WriteMsgCh:
			go s.writeMsg(msg)

		}
	}
}

func (s *peer)handleLogin(msgContent []byte,addr string){
	userNode := getLogUserInfo(msgContent,addr)
	if userNode.UserInfo.UserName == "" {
		err := "getLogUserInfo fail,please check the input Userinfo"
		doErr(err,s.WriteMsgCh)
		return
	}

	fmt.Println("UserName: ",userNode.UserInfo.UserName,"(",userNode.Ip,":",userNode.Port,")"," LogIn")

	found := false
	for node, _ := range userList {
		if node.UserInfo == userNode.UserInfo {
			found = true
			break
		}
	}

	if !found {
		userList[userNode] = struct{}{}
	}else{
		errMsg := "this userName have used"

		doErr(errMsg,s.WriteMsgCh)
		return
	}

	s.sendUserInfo()

	return
}

func (s *peer)handleGetUset(content []byte,addr string){
	if !findUserFromAddr(addr) {
		err := "This user does not have permissions,please login"

		doErr(err,s.WriteMsgCh)
		return
	}
	s.sendUserList()
}

func (s *peer)handleLogout(content []byte,addr string){
	var contentMsg  common.StLogoutMessage
	err := json.Unmarshal(content,&contentMsg)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return
	}

	fmt.Println("handleLogout	","user ",contentMsg.UserName,"address ",addr,"want to logout p2p network")

	for v, _ := range userList {
		if v.UserInfo.UserName == contentMsg.UserName {
			delete(userList, v)
			break
		}
	}

	s.sendUserInfo()

}

func (s *peer)handleTrans(content []byte,addr string){
	var msg  common.Handshack
	err := json.Unmarshal(content,&msg)
	if err != nil {
		fmt.Println("handleTrans Unmarshal,err: ",err)
		return
	}

	s.writeAddr, err = net.ResolveUDPAddr("udp",msg.To)
	if err != nil {
		fmt.Println("handleTrans ResolveUDPAddr fail,err: ",err)
		return
	}

	writeMsg := make([]byte,0,common.BUFFSIZE)
	writeMsg = append(writeMsg,common.S2PTRANSMSG)

	reply := make(chan error)

	writeMsg = append(writeMsg,content...)

	sMsg := &sendMsg{writeMsg,reply}

	go func(msg *sendMsg){
		s.WriteMsgCh <- msg
	}(sMsg)

	select {
	case err := <- reply:
		if err != nil {
			fmt.Println("write msg fail,err:",err)
			return
		}
	}
}

func (s *peer)sendUserList() {
	for msg, _ := range userList {
		uMsgInfo := make([]byte,0,common.BUFFSIZE)
		uMsgInfo = append(uMsgInfo,common.USERINFO)

		userMsgInfo, err := json.Marshal(msg)
		if err != nil {
			fmt.Println("sendUserList Marshal fail,err:",err)
			return
		}

		uMsgInfo = append(uMsgInfo,userMsgInfo...)

		uReply := make(chan error)
		uMsg := &sendMsg{uMsgInfo,uReply}

		go func(msg *sendMsg){
			s.WriteMsgCh <- msg
		}(uMsg)

		select {
		case err := <- uReply:
			if err != nil {
				fmt.Println("write msg fail,err:",err)
				return
			}
		}
	}
}

func getLogUserInfo(msg []byte,addr string)common.StUserListNode{
	userNode := common.StUserListNode{}
	var content common.StLoginMessage
	err := json.Unmarshal(msg,&content)
	if err != nil {
		fmt.Println("getLogUserInfo fail,err: ",err)
		return userNode
	}

	userNode.UserInfo.UserName = content.UserName

	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Println("getLogUserInfo		"," SplitHostPort fail,err: ",err)
		return common.StUserListNode{}
	}
	userNode.Ip = ip
	userNode.Port,_ = strconv.Atoi(port)

	return userNode
}

func (s *peer)sendUserInfo() {

	userLen := len(userList)

	for k,_ := range userList {
		replyCh := make(chan error)

		sizeMsg := make([]byte,0,common.BUFFSIZE)
		sizeMsg = append(sizeMsg,common.USERCOUNT)

		userMsg, err := json.Marshal(userLen)
		if err != nil {
			fmt.Println("handleLogin Marshal fail,err:",err)
			doErr(err.Error(),s.WriteMsgCh)
			return
		}

		s.writeAddr,err = net.ResolveUDPAddr("udp",k.Ip + ":" + strconv.Itoa(k.Port))
		if err != nil {
			fmt.Println("handleLogin ResolveUDPAddr fail,err: ",err)
			doErr(err.Error(),s.WriteMsgCh)
			return
		}
		sizeMsg = append(sizeMsg,userMsg...)
		sMsg := &sendMsg{sizeMsg,replyCh}

		go func(sMsg *sendMsg){
			s.WriteMsgCh <- sMsg
		}(sMsg)

		select {
		case err := <- replyCh:
			if err != nil {
				fmt.Println("write msg fail,err:",err)
				doErr(err.Error(),s.WriteMsgCh)
			}
		}
	}

	for k,_ := range userList {
		s.writeAddr,_ =  net.ResolveUDPAddr("udp",k.Ip + ":" + strconv.Itoa(k.Port))

		s.sendUserList()
	}


}

func doErr(errMsg string,WriteMsgCh chan *sendMsg) {
	fmt.Println(errMsg)

	eMsg := make([]byte,0,common.BUFFSIZE)

	eMsg = append(eMsg,common.ERRORMSG)

	tMsg, err := json.Marshal(errMsg)
	if err != nil {
		fmt.Println("doErr Marshal fail,err: ",err)
		return
	}
	eMsg = append(eMsg,tMsg...)

	reply := make(chan error)
	sMsg := &sendMsg{eMsg,reply}

	go func(){
		WriteMsgCh <- sMsg
	}()

	select {
	case err := <- reply:
		if err != nil {
			fmt.Println("write msg fail,err:",err)
			return
		}
	}
}

func deleteUserFromAddr(addr string) {
	for k,_ := range userList {
		userAddr := k.Ip + ":" + strconv.Itoa(k.Port)
		if userAddr == addr {
			delete(userList,k)
			return
		}
	}

	return
}

func findUserFromAddr(addr string)bool {
	for k,_ := range userList {
		userAddr := k.Ip + ":" + strconv.Itoa(k.Port)
		if userAddr == addr {
			return true
		}
	}

	return false
}
