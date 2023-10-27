package ark_ssh

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

/**
 * 封装的ssh session，包含原生的ssh.Ssssion及其标准的输入输出管道，同时记录最后的使用时间
 * @attr   session:原生的ssh session，in:绑定了session标准输入的管道，out:绑定了session标准输出的管道，lastUseTime:最后的使用时间
 */
type SSHSession struct {
	session     *ssh.Session
	in          chan string
	out         chan string
	brand       string
	lastUseTime time.Time
}

/**
 * 创建一个SSHSession，相当于SSHSession的构造函数
 * @param user ssh连接的用户名, password 密码, ipPort 交换机的ip和端口
 * @return 打开的SSHSession，执行的错误
 */
func NewSSHSession(user, password, ipPort string) (*SSHSession, error) {
	sshSession := new(SSHSession)
	if err := sshSession.createConnection(user, password, ipPort); err != nil {
		LogDebug("NewSSHSession createConnection error:%s", err.Error())
		return nil, err
	}
	if err := sshSession.muxShell(); err != nil {
		LogDebug("NewSSHSession muxShell error:%s", err.Error())
		return nil, err
	}
	if err := sshSession.start(); err != nil {
		LogDebug("NewSSHSession start error:%s", err.Error())
		return nil, err
	}
	sshSession.lastUseTime = time.Now()
	sshSession.brand = ""
	return sshSession, nil
}

/**
 * 获取最后的使用时间
 * @return time.Time
 */
func (s *SSHSession) GetLastUseTime() time.Time {
	return s.lastUseTime
}

/**
 * 更新最后的使用时间
 */
func (s *SSHSession) UpdateLastUseTime() {
	s.lastUseTime = time.Now()
}

/**
 * 连接交换机，并打开session会话
 * @param user ssh连接的用户名, password 密码, ipPort 交换机的ip和端口
 * @return 执行的错误
 */
func (s *SSHSession) createConnection(user, password, ipPort string) error {
	LogDebug("<Test> Begin connect")

	// 创建一个20秒的定时器
	timer := time.After(20 * time.Second)

	// 在goroutine中执行client.Dial()函数
	resultChan := make(chan *ssh.Session, 1)
	errChan := make(chan error, 1)
	go func() {
		client, err := ssh.Dial("tcp", ipPort, &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         20 * time.Second,
			Config: ssh.Config{
				Ciphers: []string{
					"aes128-ctr",
					"aes192-ctr",
					"aes256-ctr",
					"aes128-gcm@openssh.com",
					"aes256-gcm",
					"aes128-gcm",
					"arcfour256",
					"arcfour128",
					"aes128-cbc",
					"aes256-cbc",
					"3des-cbc",
					"des-cbc",
				},
				KeyExchanges: []string{
					"diffie-hellman-group-exchange-sha256",
					"diffie-hellman-group1-sha1",
					"diffie-hellman-group-exchange-sha1",
					"diffie-hellman-group14-exchange-sha1",
					"diffie-hellman-group14-sha256",
					"diffie-hellman-group14-sha1",
					"ecdh-sha2-nistp256",
				},
			},
		})
		if err != nil {
			errChan <- err
			return
		}
		session, err := client.NewSession()
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- session
	}()

	// 等待client.Dial()函数执行完成或定时器超时
	select {
	case session := <-resultChan:
		s.session = session
		LogDebug("<Test> End new session")
		return nil
	case err := <-errChan:
		LogDebug("SSH Dial err:%s", err.Error()+ipPort)
		return err
	case <-timer:
		LogDebug("SSH Dial timeout" + ipPort)
		return errors.New("SSH Dial timeout" + ipPort)
	}
}

/**
 * 启动多线程分别将返回的两个管道中的数据传输到会话的输入输出管道中
 * @return 错误信息error
 */
func (s *SSHSession) muxShell() error {
	defer func() {
		if err := recover(); err != nil {
			LogError("SSHSession muxShell err:%s", err)
		}
	}()
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,      // disable echoing
		ssh.TTY_OP_ISPEED: 115200, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 115200, // output speed = 14.4kbaud
	}
	if err := s.session.RequestPty("xterm", 255, 80, modes); err != nil {
		LogError("RequestPty error:%s", err)
		return err
	}
	w, err := s.session.StdinPipe()
	if err != nil {
		LogError("StdinPipe() error:%s", err.Error())
		return err
	}
	r, err := s.session.StdoutPipe()
	if err != nil {
		LogError("StdoutPipe() error:%s", err.Error())
		return err
	}

	in := make(chan string, 1024)
	out := make(chan string, 1024)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				LogError("Goroutine muxShell write err:%s", err)
			}
		}()
		for cmd := range in {
			_, err := w.Write([]byte(cmd + "\n"))
			if err != nil {
				LogDebug("Writer write err:%s", err.Error())
				return
			}
		}
	}()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				LogError("Goroutine muxShell read err:%s", err)
			}
		}()
		var (
			buf [65 * 1024]byte
			t   int
		)
		for {
			n, err := r.Read(buf[t:])
			if err != nil {
				LogDebug("Reader read err:%s", err.Error())
				return
			}
			t += n
			out <- string(buf[:t])
			t = 0
		}
	}()
	s.in = in
	s.out = out
	return nil
}

/**
 * 开始打开远程ssh登录shell，之后便可以执行指令
 * @return 错误信息error
 */
func (s *SSHSession) start() error {
	if err := s.session.Shell(); err != nil {
		LogError("Start shell error:%s", err.Error())
		return err
	}
	//等待登录信息输出
	s.ReadChannelExpect(time.Second, "#", ">", "]")
	return nil
}

/**
 * 检查当前session是否可用,通过向管道中发送一个回车，若匹配到字符则表示当前管道可用
 * @return bool
 * @author gulilin 2023/8/7 17:48
 */
func (s *SSHSession) CheckSelf() bool {
	defer func() {
		if err := recover(); err != nil {
			LogError("SSHSession CheckSelf err:%s", err)
		}
	}()

	s.WriteChannel("\n")
	result := s.ReadChannelExpect(2*time.Second, "#", ">", "]")
	if strings.Contains(result, "#") ||
		strings.Contains(result, ">") ||
		strings.Contains(result, "]") {
		return true
	}
	return false
}

/**
 * 获取当前SSH到的交换机的品牌
 * @return string （huawei,h3c,cisco）
 */
func (s *SSHSession) GetSSHBrand() string {
	defer func() {
		if err := recover(); err != nil {
			LogError("SSHSession GetBrand err:%s", err)
		}
	}()
	if s.brand != "" {
		return s.brand
	}
	//显示版本后需要多一组空格，避免版本信息过多需要分页，导致分页指令第一个字符失效的问题
	s.WriteChannel("dis version", "     ",
		"show version", "     ",
		"list mode", "     ",
		"show privilege", "     ",
		"uname -s", "     ")
	result, _ := s.ReadChannelTiming(15)
	result = strings.ToLower(result)
	if strings.Contains(result, HUAWEI) || strings.Contains(result, HUARONG) || strings.Contains(result, FutureMatrix) {
		LogDebug("The switch brand is <huawei>.")
		s.brand = HUAWEI
	} else if strings.Contains(result, H3C) {
		LogDebug("The switch brand is <h3c>.")
		s.brand = H3C
	} else if strings.Contains(result, SANGFOR) {
		LogDebug("The switch brand is <sangfor>.")
		s.brand = SANGFOR
	} else if strings.Contains(result, AnShi) || strings.Contains(result, "fit mode") || strings.Contains(result, "fat mode") {
		LogDebug("The switch brand is <anshi>.")
		s.brand = AnShi
	} else if strings.Contains(result, LINUX) {
		LogDebug("The device brand is <linux>.")
		s.brand = LINUX
	} else if strings.Contains(result, DIPU) {
		LogDebug("The switch vendor is <dipu>.")
		s.brand = DIPU
	} else if strings.Contains(result, "current privilege") {
		LogDebug("The switch vendor is <zte>.")
		s.brand = ZTE
	} else if strings.Contains(result, CISCO) {
		LogDebug("The switch brand is <cisco>.")
		s.brand = CISCO
	}
	return s.brand
}

/**
 * SSHSession的关闭方法，会关闭session和输入输出管道
 */
func (s *SSHSession) Close() {
	defer func() {
		if err := recover(); err != nil {
			LogError("SSHSession Close err:%s", err)
		}
	}()
	if err := s.session.Close(); err != nil {
		LogError("Close session err:%s", err.Error())
	}
	close(s.in)
	close(s.out)
}

/**
 * 向管道写入执行指令
 * @param cmds... 执行的命令（可多条）
 */
func (s *SSHSession) WriteChannel(cmds ...string) {
	LogDebug("WriteChannel <cmds=%v>", cmds)
	for _, cmd := range cmds {
		s.in <- cmd
	}
}

/**
 * 从输出管道中读取设备返回的执行结果，若输出流间隔超过timeout或者包含expects中的字符便会返回
 * @param	timeout 从设备读取不到数据时的超时等待时间（超过超时等待时间即认为设备的响应内容已经被完全读取）, expects...:期望得到的字符（可多个），得到便返回
 * @return 	从输出管道读出的返回结果
 * @author gulilin 2023/7/31 10:31
 */
func (s *SSHSession) ReadChannelExpect(timeout time.Duration, expects ...string) string {
	LogDebug("ReadChannelExpect <wait timeout = %d>", timeout/time.Millisecond)
	output := ""
	isDelayed := false
	for i := 0; i < 100; i++ { //最多从设备读取100次，避免方法无法返回
		time.Sleep(time.Millisecond * 100) //每次睡眠0.1秒，使out管道中的数据能积累一段时间，避免过早触发default等待退出
		newData := s.readChannelData()
		LogDebug("ReadChannelExpect: read chanel buffer: %s", newData)
		if newData != "" {
			output += newData
			isDelayed = false
			continue
		}
		for _, expect := range expects {
			if strings.Contains(output, expect) {
				return output
			}
		}
		//如果之前已经等待过一次，则直接退出，否则就等待一次超时再重新读取内容
		if !isDelayed {
			LogDebug("ReadChannelExpect: delay for timeout")
			time.Sleep(timeout)
			isDelayed = true
		} else {
			return output
		}
	}
	return output
}

/**
 * 从输出管道中读取设备返回的执行结果，若匹配到prompt则直接返回,否则输出流间隔超过timeout便会返回
 * @param	timeout,超时时间
 * @return 	string，拼接的通道回显,bool若为false则表示超时退出
 * @author gulilin 2023/7/31 10:27
 */
func (s *SSHSession) ReadChannelTiming(timeout int) (string, bool) {
	output := ""
	// 编译正则表达式，匹配所有可能的提示符
	reg := regexp.MustCompile(PROMPT)
	//设定每次从管道取值的间隔（微秒）
	loopDelay := 100
	loops := timeout * 1000 / loopDelay
	//根据timeout（秒）动态循环某个次数
	for i := 0; i < loops; i++ {
		time.Sleep(time.Millisecond * time.Duration(loopDelay))
		newData := s.readChannelData()
		//如果从管道中读取到了内容
		if newData != "" {
			output += newData
			matches := reg.FindAllString(output, -1)
			if len(matches) >= 1 {
				return output, true
			}
		}
	}
	return output, false
}

/**
 * 清除管道缓存的内容，避免管道中上次未读取的残余内容影响下次的结果
 */
func (s *SSHSession) ClearChannel() {
	s.readChannelData()
}

/**
 * 清除管道缓存的内容，避免管道中上次未读取的残余内容影响下次的结果
 */
func (s *SSHSession) readChannelData() string {
	output := ""
	for {
		select {
		case channelData, ok := <-s.out:
			if !ok {
				//如果out管道已经被关闭，则停止读取，否则<-s.out会进入无限循环
				return output
			}
			output += channelData
		default:
			return output
		}
	}
}
