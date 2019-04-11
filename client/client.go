package main

import (
	"MyCode/udpnat/common"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	app = cli.NewApp()

	clientPortFlag = cli.IntFlag{
		Name:"cport",
		Value:common.CLIENT_PORT,
		Usage:"Client port",
	}

	clientIpFlag = cli.StringFlag{
		Name:	"cip",
		Value:	common.CLIENT_IP,
		Usage:	"Client Listen ip",
	}

	serverPortFlag = cli.IntFlag{
		Name:"sport",
		Value:common.SERVER_PORT,
		Usage:"Server Port",
	}

	serverIpFlag = cli.StringFlag{
		Name:	"sip",
		Value:	common.SERVER_IP,
		Usage:	"Server Listen ip",
	}
)

var userList map[common.StUserListNode]struct{}

var self common.StUserListNode

type peer struct{
	conn *net.UDPConn
	serverAddr string

	writeMsg   chan stWriteMsg

	gotreply   map[common.Handshack]reply

	state     map[connectPeer]common.STATE

}

type connectPeer struct {
	serverAddr	string
	localAddr   string
	peerAddr  string
}

type stWriteMsg struct {
	msgContent  []byte
	remoteAddr  string
}

type reply struct{
	matched chan <- bool
}

type (
	stP2pMsg struct {
	}

	stUserCount struct {
	}

	stUserInfo struct {
	}

	stS2pTransMsg struct {
	}

	stP2PTransAck struct {
	}

	stErrorMsg struct {

	}
)

type stPackage interface {
	handle(p *peer,msg []byte,from *net.UDPAddr) error
}


func init(){
	app.Name = "udpNatClient"
	app.Flags = []cli.Flag{
		clientPortFlag,
		clientIpFlag,
		serverPortFlag,
		serverIpFlag,
	}

	app.Action = udpClient
}


func main(){
	app.Run(os.Args)

	fmt.Println("main end...")
}

func udpClient(ctx *cli.Context) error{
	var name string

	fmt.Printf("Please input your user name:>")
	scanner := bufio.NewScanner(os.Stdin)

	if scanner.Scan(){
		name = scanner.Text()
	}

	var logMsg common.StLoginMessage
	logMsg.UserName = name

	self.UserInfo.UserName = name

	serverAddress := ctx.GlobalString(serverIpFlag.Name) + ":" + strconv.Itoa(ctx.GlobalInt(serverPortFlag.Name))
	listenAddress := ctx.GlobalString(clientIpFlag.Name) + ":" + strconv.Itoa(ctx.GlobalInt(clientPortFlag.Name))

	listenAddr, err := net.ResolveUDPAddr("udp",listenAddress)
	if err != nil {
		fmt.Println("ResolveUDPAddr fail,err:",err)
		return err
	}

	serverAddr, err := net.ResolveUDPAddr("udp",serverAddress)
	if err != nil {
		fmt.Println("ResolveUDPAddr fail,err:",err)
		return err
	}

	conn, err := net.ListenUDP("udp",listenAddr)
	if err != nil {
		fmt.Println("ListenUDP fail,err: ",err)
		return err
	}

	doWriteLoginMsg(logMsg,conn,serverAddr)

	if err := doListenUDP(conn,serverAddress); err != nil {
		fmt.Println("doListenUDP fail, err: ",err)
		return err
	}

	return nil
}

func doWriteLoginMsg(msg common.StLoginMessage,conn *net.UDPConn,serverAddr *net.UDPAddr) {
	msgBuff := make([]byte,0,common.BUFFSIZE)
	msgBuff = append(msgBuff,common.LOGIN)
	buff, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("doWriteLoginMsg		"," Marshal fail,err:",err)
		return
	}
	msgBuff = append(msgBuff,buff...)

	_ , err = conn.WriteToUDP(msgBuff,serverAddr)
	if err != nil {
		fmt.Println("doWriteLoginMsg		"," write message fail,err:",err)
		return
	}
}

func doListenUDP(conn *net.UDPConn,serverAddr string) error{
	p := newPeer(conn,serverAddr)

	go p.readLoop()

	go p.writeLoop()

	go p.stop()


	menu()

	p.console()


	return nil
}

func newPeer(conn *net.UDPConn,serverAddr string) *peer{
	peer := &peer{
		conn:	conn,
		writeMsg:make(chan stWriteMsg),
		gotreply:make(map[common.Handshack]reply),
		serverAddr:serverAddr,
		state:make(map[connectPeer]common.STATE),
	}


	return peer
}

func (p *peer) readLoop() {
	defer p.conn.Close()

	for{
		buf := make([]byte,common.BUFFSIZE)
		nRead, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("ReadFromUDP fail,err: ",err)
			return
		}
		p.handlePacket(from,buf[:nRead])
	}
}

func (p *peer) writeLoop() {
	for {
		select {
		case msg := <- p.writeMsg:
			err := sendMsg(p.conn,msg.msgContent,msg.remoteAddr)
			if err != nil {
				fmt.Println("sendMsg fail,err: ",err)
				return
			}
		}
	}
}

func (p *peer) handlePacket(from *net.UDPAddr,bufs []byte) error {
	mPackage,msg := decodePacket(bufs)
	if mPackage == nil {
		fmt.Println("unknow package type")
		return errors.New("unknow package type")
	}

	err := mPackage.handle(p,msg,from)
	if err != nil {

	}


	return nil
}

func decodePacket(bufs []byte)(stPackage,[]byte) {
	var req stPackage
	switch pType := bufs[0];pType {
	case common.P2PMESSAGE:
		req = new(stP2pMsg)
	case common.P2PTRANSACK:
		req = new(stP2PTransAck)
	case common.USERCOUNT:
		req = new(stUserCount)
	case common.USERINFO:
		req = new(stUserInfo)
	case common.P2PTRANSMSG:		//接收到客户端的握手消息的处理机制与接收到服务器转发的握手消息机制相同
		req = new(stS2pTransMsg)
	case common.S2PTRANSMSG:
		req = new(stS2pTransMsg)
	case common.ERRORMSG:
		req = new(stErrorMsg)
	default:
		return nil,bufs[1:]
	}

	return req,bufs[1:]
}

func (p *peer)console() {
	input := bufio.NewScanner(os.Stdin)
	fmt.Printf(">")
	for input.Scan() {
		command := input.Text()
		p.parseCommand(command)
		fmt.Printf(">")
	}
}

func (p *peer)stop(){
	sigc := make(chan os.Signal,1)
	signal.Notify(sigc,syscall.SIGINT,syscall.SIGTERM)
	defer signal.Stop(sigc)

	<- sigc

	fmt.Println("Got interrupt, shutting down...")

	p.exit()
}

func menu(){
	fmt.Println("====================================================================")
	fmt.Println("*  You can input you command:                                      *")
	fmt.Println("*  Command Type:\"login\",\"send\",\"logout\",\"getuser\",\"exit\" *")
	fmt.Println("*  logout UserName(your address should right)             		    *")
	fmt.Println("*  login  UserName(your User name not used)               			*")
	fmt.Println("*  Example : send Username Message                        			*")
	fmt.Println("*  logout UserName(your address should right)             			*")
	fmt.Println("*  getuser                                                			*")
	fmt.Println("====================================================================")
}

func (p *peer)parseCommand(cmd string){
	cmds := strings.Split(cmd," ")

	switch cmds[0] {
	case "send":
		if len(cmds) != 3 {
			fmt.Println("argv err")
			fmt.Println("send UserName Message")
			return
		}
		go p.sendHandle(cmds[1],cmds[2])
	case "logout":
		if len(cmds) != 2{
			fmt.Println("argv err")
			fmt.Println("logout userName")
			return
		}

		go p.logout(cmds[1])
	case "login":
		if len(cmds) != 2{
			fmt.Println("argv err")
			fmt.Println("logout userName")
			return
		}
		go p.login(cmds[1])
	case "getuser":
		go p.getUser()
	case "exit":
		go p.exit()
	default:
		fmt.Println("You entered the wrong command,Please check!!!")
	}
}

func (p *peer)sendHandle(userName string,message string){
	//通过用户名取出ip,端口
	isFind, userIp, userPort := findUser(userName)

	if !isFind {
		fmt.Println("do not find this user,username:",userName)
		return
	}

	isSelf, selfIp, selfPort := findSelf(self.UserInfo.UserName)

	if !isSelf {
		fmt.Println("Server have error message")
		return
	}

	localAddr := selfIp + ":" + strconv.Itoa(selfPort)

	msg := make([]byte,0,common.BUFFSIZE)

	msgContent, err := json.Marshal(message)
	if err != nil {
		fmt.Println("sendHandle		","Marshal fail,err: ",err)
		return
	}

	peerAddress := userIp + ":" + strconv.Itoa(userPort)

	connPeer := connectPeer{
		serverAddr:p.serverAddr,
		localAddr:localAddr,
		peerAddr:peerAddress,
	}

	var typeFlag bool

	//判断此链接是否打洞过
	if v,ok := p.state[connPeer];!ok {
		p.state[connPeer] = common.P2P_MESSAGR_TRANS

		typeFlag = true

	}else {
		if v == common.P2P_MESSAGR_TRANS {
			typeFlag = true
		}else{
			typeFlag = false
		}
	}

	//此链接没有打洞过则发消息对对端，ＮＡＴ设备会记录发出的链接请求，同时发送消息给服务器，服务器转发消息给对端，对端回应ACK消息给本机，
	//由于ＮＡＴ设备记录了本机给对端发送的链接请求，则对端回应过来的消息NAT设备会当成发出消息的回应，会到达本机，而本机发送给对端的消息会被ＮＡＴ设备丢弃.

	if typeFlag {
		flag := p.handshake(connPeer.localAddr,connPeer.peerAddr,connPeer.serverAddr)
		if flag == false {
			fmt.Println("handshake fail,Network Address Translation fail.")
			return
		}
		p.state[connPeer] = common.P2P_MESSAGT_CONNECT
	}

	fmt.Println("p2p Module")

	msg = append(msg,common.P2PMESSAGE)
	msg = append(msg,msgContent...)

	writeMsg := stWriteMsg{msg,peerAddress}
	p.writeMsg <- writeMsg
}

func (p *peer)logout(name string) {
	if name != self.UserInfo.UserName {
		err := "Please enter your own username"
		fmt.Println(err)
		return
	}

	user := common.StLogoutMessage{name}

	msg := make([]byte,0,common.BUFFSIZE)
	msg = append(msg,common.LOGOUT)
	msgContent, err := json.Marshal(user)
	if err != nil {
		fmt.Println("logout Marshal fail,err: ",err)
		return
	}
	msg = append(msg,msgContent...)

	writeMsg := stWriteMsg{msg,p.serverAddr}
	p.writeMsg <- writeMsg


	return
}

func (p *peer)login(name string){
	userName := common.StLoginMessage{name}
	remoteAddr,err := net.ResolveUDPAddr("udp",p.serverAddr)
	if err != nil {
		fmt.Println("login fail,err: ",err)
		return
	}
	doWriteLoginMsg(userName,p.conn,remoteAddr)
}

func (p *peer)getUser() {
	msg := make([]byte,0,common.BUFFSIZE)
	msg = append(msg,common.GETUSER)

	writeMsg := stWriteMsg{msg,p.serverAddr}
	p.writeMsg <- writeMsg
}

func (p *peer)exit() {
	name := self.UserInfo.UserName

	p.logout(name)
	//等待发送出去logout消息
	time.Sleep(time.Millisecond)
	os.Exit(0)
}

func (req *stP2pMsg)handle(p *peer,msg []byte,from *net.UDPAddr) error{
	ip := from.IP.String()
	port := from.Port
	var name string
	var flag bool

	for k,_ := range userList {
		if k.Port == port && k.Ip == ip {
			name = k.UserInfo.UserName
			flag = true
			break
		}
	}

	var msgBuff string

	err := json.Unmarshal(msg,&msgBuff)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return err
	}

	if flag {
		fmt.Println("Recv message: ","from ","[",name,"(",ip,":",port,")]","   msg   :",msgBuff)
	}else{
		fmt.Println("Recv message from unknow user"," [(",ip,":",port,")]","	   msg   :",msgBuff)
		fmt.Println("Please send command to Server <getuser> ")
	}


	return nil
}

func (req *stUserCount)handle(p *peer,msg []byte,from *net.UDPAddr) error{
	var nCount int
	err := json.Unmarshal(msg,&nCount)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return err
	}

	userList = make(map[common.StUserListNode]struct{})

	fmt.Println("*********login user info*********")


	return nil
}

func (req *stUserInfo)handle(p *peer,msg []byte,from *net.UDPAddr) error{
	var msgUserInfo common.StUserListNode
	err := json.Unmarshal(msg,&msgUserInfo)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return err
	}

	userList[msgUserInfo] = struct{}{}

	fmt.Println("userName: ",msgUserInfo.UserInfo.UserName,"(",msgUserInfo.Ip,":",msgUserInfo.Port,")")


	return nil
}

func (req *stS2pTransMsg)handle(p *peer,msg []byte,from *net.UDPAddr) error {
	var contentMsg common.Handshack
	err := json.Unmarshal(msg,&contentMsg)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return err
	}

	sMsg := make([]byte,0,common.BUFFSIZE)
	sMsg = append(sMsg,common.P2PTRANSACK)


	sMsg = append(sMsg,msg...)

	writeMsg := stWriteMsg{sMsg,contentMsg.From}
	p.writeMsg <- writeMsg


	return nil
}

func (req *stP2PTransAck)handle(p *peer,msg []byte,from *net.UDPAddr) error{

	var contentMsg common.Handshack

	err := json.Unmarshal(msg,&contentMsg)
	if err != nil {
		fmt.Println("Unmarshal fail,err: ",err)
		return err
	}

	if v,ok := p.gotreply[contentMsg];ok {
		delete(p.gotreply,contentMsg)
		v.matched <- true
	}else{
		fmt.Println("from the ACK,can't find the send SYN message")
	}


	return nil
}

func (req *stErrorMsg)handle(p *peer,msg []byte,from *net.UDPAddr) error {
	var errMsg string
	err := json.Unmarshal(msg,&errMsg)
	if err != nil {
		fmt.Println("stErrorMsg handle fail,err: ",err)
		return err
	}

	fmt.Println("Receive a server Error response"," error message: ",errMsg)

	return nil
}

func sendMsg(conn *net.UDPConn,msg []byte,reAddress string)error{
	remoteAddr, err := net.ResolveUDPAddr("udp",reAddress)
	if err != nil {
		fmt.Println("sendMsg		","ResolveUDPAddr fail,err:",err)
		return err
	}

	_, err = conn.WriteToUDP(msg,remoteAddr)
	if err != nil {
		fmt.Println("ResolveUDPAddr fail,err:",err)
		return err
	}

	return nil
}

func findUser(userName string) (bool,string,int) {
	for user, _ := range userList {
		if user.UserInfo.UserName == userName {

			return true,user.Ip,user.Port
		}
	}

	return false,"",0
}

func findSelf(self string) (bool,string,int){
	for user, _ := range userList {
		if user.UserInfo.UserName == self {

			return true,user.Ip,user.Port
		}
	}

	return false,"",0
}

//通过握手来进行打洞
func (p *peer)handshake(localAddr,peerAddr,serverAddr string) bool{
	//先给对端发送握手消息
	msg := make([]byte,0,common.BUFFSIZE)
	msg = append(msg,common.P2PTRANSMSG)

	shackMsg := common.Handshack{localAddr,peerAddr,common.HANDSHACK_MESSAGE}
	sMsg,err := json.Marshal(shackMsg)
	if err != nil {
		fmt.Println("sendHandle:		","Marshal fail,err: ",err)
		return false
	}

	msg = append(msg,sMsg...)

	//先给对端发送握手消息
	writeMsg := stWriteMsg{msg,peerAddr}
	p.writeMsg <- writeMsg

	//等待对端回复握手消息的ACK
	resultCh := make(chan bool)
	p.gotreply[shackMsg] = reply{resultCh}

	var flag bool

	select {
	case <- resultCh:
		flag = true
	case <- time.After(common.P2PSHAKETIMEOUT):
		fmt.Println("handshake		","time out","send message to Server for trans")
		flag = false
	}

	if flag {
		return true
	}else{
		//请求服务器转发握手消息
		cMsg := make([]byte,0,common.BUFFSIZE)
		cMsg = append(cMsg,common.P2PTRANS)
		cMsg = append(cMsg,sMsg...)

		writeMsg = stWriteMsg{cMsg,serverAddr}
		p.writeMsg <- writeMsg
	}

	select {
	case <- resultCh:
		 return true
	case <- time.After(common.P2PSHAKETIMEOUT):
		fmt.Println("handshake		","time out")
		return false
	}

}