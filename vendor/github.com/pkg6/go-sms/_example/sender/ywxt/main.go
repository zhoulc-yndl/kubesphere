package main

import (
	"fmt"
	gosms "github.com/pkg6/go-sms"
	"github.com/pkg6/go-sms/gateways/ywxt"
)

func main() {
	var number = gosms.NoCodePhoneNumber(18817384537)
	var gateway = ywxt.GateWay("CWIFT云平台", "aa86d7ad79e44649adef272cd7132358")
	var message = gosms.MessageTemplate("1004", gosms.MapStrings{
		//sendCode 或 verifyCode
		"action": "sendCode",
		"notice": "您的验证码为345678，请于5分钟内正确输入，如非本人操作，请忽略此短信",
	})
	result, err := gosms.Sender(number, message, gateway)
	if resp, ok := result.ClientResult.Response.(ywxt.Response); ok {
		fmt.Println(resp)
	}
	fmt.Println(err)
}
