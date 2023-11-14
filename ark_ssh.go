package arkssh

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/sirikothe/gotextfsm"
	"golang.org/x/crypto/ssh"
)

const (
	HUAWEI       = "huawei"
	HUARONG      = "huarong"
	FutureMatrix = "futurematrix"
	AnShi        = "anshi"
	SANGFOR      = "sangfor"
	H3C          = "h3c"
	CISCO        = "cisco"
	LINUX        = "linux"
	DIPU         = "dptech"
	ZTE          = "zte"
	PROMPT       = `\n<[^!]{1,100}>\s*$|\n\[[^\]]{1,100}\]\s*$|\n[^!\n ]{3,30}[^ \n]#\s*$|\n.*\[[^\]]{1,100}\]#\s*$`
)

var IsLogDebug bool

type Device struct {
	ID             string `bson:"id,omitempty" json:"id,omitempty" unique:"true"`
	DCName         string `bson:"dc_name,omitempty" json:"dc_name,omitempty"`
	DCType         string `bson:"dc_type,omitempty" json:"dc_type,omitempty"`
	IP             string `bson:"ip,omitempty" json:"ip,omitempty"`
	Port           string `bson:"port,omitempty" json:"port,omitempty"`
	Username       string `bson:"username,omitempty" json:"username,omitempty"`
	Password       string `bson:"password,omitempty" json:"password,omitempty"`
	Brand          string `bson:"brand,omitempty" json:"brand,omitempty"`
	Status         string `bson:"status,omitempty" json:"status,omitempty"`
	SSHStatus      string `bson:"ssh_status,omitempty" json:"ssh_status,omitempty"`
	WEBStatus      string `bson:"web_status,omitempty" json:"web_status,omitempty"`
	CreateTime     string `bson:"create_time,omitempty" json:"create_time,omitempty"`
	LastUpdate     string `bson:"last_update,omitempty" json:"last_update,omitempty"`
	NotPong        int    `bson:"not_pong,omitempty" json:"not_pong,omitempty"`                 //探测主机22端口连续失败次数
	ProdTestSimple bool   `bson:"prod_test_simple,omitempty" json:"prod_test_simple,omitempty"` //是否为生产环境测试用例使用设备..

	// 推送命令相关
	Cmds                     []string               `bson:"cmds,omitempty" json:"cmds,omitempty"`
	Timeout                  int                    `bson:"timeout,omitempty" json:"timeout,omitempty"`
	SendStatus               string                 `bson:"send_status,omitempty" json:"send_status,omitempty"` //命令推送的状态，成功为success
	RawResult                string                 `bson:"raw_result,omitempty" json:"raw_result,omitempty"`   //原始的回显
	MapResult                map[string]OneCMDRes   `bson:"map_result,omitempty" json:"map_result,omitempty"`   //origin_ssh使用
	ResultMap                map[string]string      `bson:"result,omitempty" json:"result,omitempty"`           //scrapli_ssh使用，将每行命令为key，结果为value写入map
	Detect                   string                 `bson:"detect,omitempty" json:"detect,omitempty"`
	UnzipTextFsmResults      bool                   `bson:"unzip_text_fsm_results,omitempty" json:"unzip_text_fsm_results,omitempty"` //是否解压TextFsmResults结果
	TextFsmTemplateFilenames []string               `bson:"textfsm_templates,omitempty" json:"textfsm_templates,omitempty"`
	TextFsmContent           string                 `bson:"textfsm_content,omitempty" json:"textfsm_content,omitempty"`
	TextFsmResults           map[string]interface{} `bson:"textfsm_results,omitempty" json:"textfsm_results,omitempty"`
	// 登录验证相关
	LoginSuccessTimes       int `bson:"login_success_times,omitempty" json:"login_success_times,omitempty"`     //登录成功次数
	LoginTotalTimes         int `bson:"login_total_times,omitempty" json:"login_total_times"`                   //登录总次数
	LoginFailContinuesTimes int `bson:"login_fail_continues_times,omitempty" json:"login_fail_continues_times"` //连续登录失败次数
}

// 单个命令的执行情况
type OneCMDRes struct {
	RES    string `bson:"res,omitempty" json:"res,omitempty"`
	Status string `bson:"status,omitempty" json:"status,omitempty"`
}

/**
 * 登录测试
 * @return bool，是否能登录
 * @author gulilin 2023/8/22 11:16
 */
func (d *Device) LoginCheck() (bool, error) {
	if d.Port == "" {
		d.Port = "22"
	}
	ipPort := d.IP + ":" + d.Port
	sshSession := new(SSHSession)
	if err := sshSession.createConnection(d.Username, d.Password, ipPort); err != nil {
		LogDebug("login failed error:%s", err.Error())
		return false, err
	}
	defer func(session *ssh.Session) {
		err := session.Close()
		if err != nil {
			LogError("Close session err:%s", err.Error())
		}
	}(sshSession.session)
	return true, nil
}

/**
 * 外部调用的统一方法，完成获取交换机的型号
 * @param user ssh连接的用户名, password 密码, ipPort 交换机的ip和端口
 * @return 设备品牌（huawei，h3c，cisco，""）和执行错误
 * @author gulilin 2023/7/10 15:27
 */
func (d *Device) GetBrand() (string, error) {
	if d.Port == "" {
		d.Port = "22"
	}
	ipPort := d.IP + ":" + d.Port
	sessionKey := d.Username + "_" + d.Password + "_" + ipPort
	sessionManager.LockSession(sessionKey)
	defer sessionManager.UnlockSession(sessionKey)

	sshSession, err := sessionManager.GetSession(d.Username, d.Password, ipPort, "")
	if err != nil {
		LogError("获取会话错误:%s", err)
		return "", err
	}
	brand := sshSession.GetSSHBrand()
	d.Brand = brand
	LogDebug("获取设备brand成功,ipPort:%s,brand:%s", ipPort, brand)

	return brand, nil
}

/**
 * 未知brand设备推送命令
 * @param	无
 * @return 无
 * @author gulilin 2023/7/10 15:27
 */
func (d *Device) RunCmdWithoutBrand() error {
	if d.Port == "" {
		d.Port = "22"
	}
	ipPort := d.IP + ":" + d.Port
	sessionKey := d.Username + "_" + d.Password + "_" + ipPort
	sessionManager.LockSession(sessionKey)
	defer sessionManager.UnlockSession(sessionKey)

	sshSession, err := sessionManager.GetSession(d.Username, d.Password, ipPort, "")
	if err != nil {
		LogError("获取会话错误:%s", err.Error())
		return err
	}
	sshSession.WriteChannel(d.Cmds...)
	result, _ := sshSession.ReadChannelTiming(10)
	d.RawResult = filterResult(result, d.Cmds[0])
	return nil
}

/**
 * 已知brand设备推送命令
 * @param	timeOut，批量推送命令的超时时间
 * @return error，无错误则直接赋值传入的device
 * @author gulilin 2023/7/10 15:27
 */
func (d *Device) RunCmdWithBrand(timeOut int) error {
	// 如果设备未携带端口，默认为22
	if d.Port == "" {
		d.Port = "22"
	}
	// 优先选择设备自带的timeout
	if d.Timeout != 0 {
		timeOut = d.Timeout
	}
	ipPort := d.IP + ":" + d.Port
	sessionKey := d.Username + "_" + d.Password + "_" + ipPort
	sessionManager.LockSession(sessionKey)
	defer sessionManager.UnlockSession(sessionKey)
	sshSession, err := sessionManager.GetSession(d.Username, d.Password, ipPort, d.Brand)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "unable to authenticate"):
			d.SendStatus = fmt.Sprintf("密码错误,IP为%s", d.IP)
		case strings.Contains(err.Error(), "reset by peer"):
			d.SendStatus = fmt.Sprintf("多次登录失败，设备拒绝连接,IP为%s", d.IP)
		case strings.Contains(err.Error(), "timed out"):
			d.SendStatus = fmt.Sprintf("登录验证连接超时,IP为%s", d.IP)
		case strings.Contains(err.Error(), "connection refused"):
			d.SendStatus = fmt.Sprintf("22端口未开,IP为%s", d.IP)
		case strings.Contains(err.Error(), "timeout sending"):
			d.SendStatus = fmt.Sprintf("发送命令连接超时,IP为%s", d.IP)
		default:
			d.SendStatus = fmt.Sprintf("其他错误:%v,IP为%s", err.Error(), d.IP)
		}
		LogError("获取会话错误:%s", d.SendStatus)
		return err
	}
	//
	successNum := 0
	rawRes := ""
	mapRes := make(map[string]OneCMDRes)
	// 循环命令，依次向管道推送
	for _, cmd := range d.Cmds {
		var one OneCMDRes
		sshSession.WriteChannel(cmd)
		ok := false
		// 单词命令的回显，是否推送成功
		one.RES, ok = sshSession.ReadChannelTiming(timeOut)
		switch {
		case ok:
			one.Status = "success"
			successNum++
		case !ok && one.RES == "":
			one.Status = "采集配置为空"
		case !ok && one.RES != "":
			one.Status = "配置采集不完整"
			LogDebug("配置采集不完整", d.IP)
		default:
			one.Status = "读回显遇到未知错误"
		}
		// 对单次命令的回显进行格式化操作
		one.RES = filterResult(one.RES, cmd)
		mapRes[cmd] = one
		rawRes += one.RES
	}
	if successNum == len(d.Cmds) {
		d.SendStatus = "success"
	} else {
		d.SendStatus = "存在部分命令采集异常"
	}
	d.RawResult = rawRes
	d.MapResult = mapRes
	//如果textfsm字段不为空则将原始的result进行解析
	parserRes := make(map[string]interface{})
	if len(d.TextFsmTemplateFilenames) > 0 {
		for i := range d.TextFsmTemplateFilenames {
			tempName := d.TextFsmTemplateFilenames[i]
			res, err := TextFsmParseViaTemplateFile(d.Brand, rawRes, tempName)
			if err != nil {
				LogDebug("TextFsm解析失败%v,采集的状态为%s,IP:%s", err, d.SendStatus, d.IP)
			}
			LogDebug("解析成功")
			//是否需要将textfsm转换后的内容解压，默认不解压,(该项用于textfsm模板中只解析一个元素的情况下)
			if d.UnzipTextFsmResults && len(res) == 1 {
				for k, v := range res[0] {
					parserRes[k] = v
				}
			} else {
				parserRes[tempName] = res
			}
		}
		d.TextFsmResults = parserRes
	} else if d.TextFsmContent != "" {
		res, err := TextFsmParseViaContent(rawRes, d.TextFsmContent)
		if err != nil {
			LogDebug("TextFsm解析失败%v,采集的状态为%s,IP:%s", err, d.SendStatus, d.IP)
		}
		LogDebug("解析成功")
		//是否需要将textfsm转换后的内容解压，默认不解压,(该项用于textfsm模板中只解析一个元素的情况下)
		if d.UnzipTextFsmResults && len(res) == 1 {
			for k, v := range res[0] {
				parserRes[k] = v
			}
		} else {
			parserRes["result"] = res
		}
		d.TextFsmResults = parserRes
	}
	return nil
}

/**
 * 对交换机执行的结果进行过滤
 * 1、处理每行回显，除去空白，tab
 * 2、将Last configuration wasXXXX统一替换成Last configuration updateed or saved
 * 3、截取第一个出现命令之后的内容
 * @paramn result:返回的执行结果（可能包含脏数据）, firstCmd:执行的第一条指令
 * @return 过滤后的执行结果
 */
func filterResult(result, firstCmd string) string {
	filteredResult := ""
	//将所有PROMPT替换成空字符串
	//re := regexp.MustCompile(PROMPT)
	//cleanResult := re.ReplaceAllString(result, "")
	cleanResult := strings.Replace(result, "\r\r\n", "\r\n", -1) //华三换行是\r\r\n
	/*
		针对华三9306特殊操作：
		port trunk permit vlan 1059 1063 1068 1082 1087 2501 to 2502 2510 3001 3100 3200 \r\n
	*/
	cleanResult2 := strings.Replace(cleanResult, " \r\n", "\r\n", -1) //针对华三9306特殊操作，
	//数组化，以换行符为分割进行数组化
	resultArray := strings.Split(cleanResult2, "\n")
	//遍历每一行回显
	for _, resultItem := range resultArray {
		//去除" \b"字段
		resultItem = strings.Replace(resultItem, " \b", "", -1)
		//去除行尾空白字符
		resultItem = strings.TrimRight(resultItem, " ")
		//判断是否包含Last configuration was，若包含则将该行整个都替换掉，以屏蔽保存时间不一样导致的每次配置比对都有差异
		if strings.Contains(resultItem, "Last configuration was") {
			resultItem = strings.Replace(resultItem, resultItem, "Last configuration updateed or saved", -1)
		}
		//拼接
		filteredResult += resultItem + "\n"
	}
	//截取第一个出现命令之后的内容
	index := strings.LastIndex(filteredResult, firstCmd+"\r")
	if index != -1 {
		filteredResult = filteredResult[index:]
		filteredResult = strings.TrimSpace(filteredResult)
	}
	return filteredResult
}

/**
 * 批量推送命令，带有brand的设备
 * @param	devices，一组包含Device结构体实例的切片，timeOut，推送命令后等待的超时时间（秒）
 * @return 	无，直接修改了原切片
 * @author gulilin 2023/7/10 16:12
 */
func BulkRunCmd(devices []Device, timeOut int) error {
	wg := sync.WaitGroup{}
	wg.Add(len(devices))
	for i := range devices {
		go func(d *Device) {
			//start := time.Now()
			defer wg.Done()
			err := d.RunCmdWithBrand(timeOut)
			//elapsed := time.Since(start)
			//LogDebug("运行时间为%s\n", elapsed)
			//LogDebug("%s----%s-----%s,运行时间为%s\n", d.IP, d.Brand, d.ResultMap, elapsed)
			if err != nil {
				LogDebug("异常:%s", err.Error())
			}
		}(&devices[i])
	}
	wg.Wait()
	return nil
}

/**
 * 将文本通过textfsm模板解析
 * @param	brand，品牌名称，waitToParse，待解析的文本，templateName，解析模板名称
 * @return  切片包map，key为属性名称，值为任意
 * @author gulilin 2023/9/21 11:41
 */
func TextFsmParseViaTemplateFile(brand string, waitToParse string, templateName string) ([]map[string]interface{}, error) {
	if brand == "" {
		return nil, errors.New("brand为空，无法进行textfsm解析")
	}
	content, err := os.ReadFile(fmt.Sprintf("common/textfsm/%s/%s", brand, templateName))
	if err != nil {
		return nil, err
	}
	template := string(content)
	fsm := gotextfsm.TextFSM{}
	err = fsm.ParseString(template)
	if err != nil {
		fmt.Printf("Error while parsing template '%s'\n", err.Error())
		return nil, err
	}
	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(waitToParse, fsm, true)
	if err != nil {
		fmt.Printf("Error while parsing input '%s'\n", err.Error())
	}
	parserDict := parser.Dict
	if len(parserDict) < 1 {
		return nil, errors.New("解析结果为空")
	}
	return parserDict, nil
}

/**
 * 将文本通过textfsm模板解析,通过直接的外参作为模板内容进行解析
 * @param	waitToParse-待解析的内容，textFmsContent-解析模板内容
 * @return 	切片包map，key为属性名称，值为任意
 * @author gulilin 2023/11/9 11:08
 */
func TextFsmParseViaContent(waitToParse string, textFmsContent string) ([]map[string]interface{}, error) {
	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(textFmsContent)
	if err != nil {
		fmt.Printf("Error while parsing template '%s'\n", err.Error())
		return nil, err
	}
	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(waitToParse, fsm, true)
	if err != nil {
		fmt.Printf("Error while parsing input '%s'\n", err.Error())
	}
	parserDict := parser.Dict
	if len(parserDict) < 1 {
		return nil, errors.New("解析结果为空")
	}
	return parserDict, nil
}

func LogDebug(format string, a ...interface{}) {
	if IsLogDebug {
		fmt.Println("[DEBUG]:" + fmt.Sprintf(format, a...))
	}

}

func LogError(format string, a ...interface{}) {
	fmt.Println("[ERROR]:" + fmt.Sprintf(format, a...))
}
