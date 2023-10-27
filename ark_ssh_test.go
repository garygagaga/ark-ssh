package arkssh

import (
	"fmt"
	"testing"
)

func TestBulkRunCmd(t *testing.T) {
	var devs []Device

	a := Device{IP: "10.103.158.5", Username: "username", Password: "admin123", Cmds: []string{"disp clock"},
		Brand: "h3c"}
	b := Device{IP: "10.103.158.5", Username: "username", Password: "admin123", Cmds: []string{"disp clock"},
		Brand: "h3c"}
	devs = append(devs, a)
	devs = append(devs, b)
	IsLogDebug = true //打开debug显示详细信息
	err := BulkRunCmd(devs, 50)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("测试完毕===============")
	for i := range devs {
		fmt.Printf("设备%s执行结果%s\n，原始回显为%s\n，按推送命令分类后的回显为%v\n",
			devs[i].IP, devs[i].SendStatus, devs[i].RawResult, devs[i].MapResult)
	}
}
