package main

import (
	"fmt"
	gosms "github.com/pkg6/go-sms"
	"github.com/pkg6/go-sms/gateways/ywxt"
)

func main() {
	appSecret := "Secret"
	sendUrl := "sendUrl"
	templateId := "templateId"
	tokenUrl := "tokenUrl"
	appName := "appName"
	smsHost := "host"
	notice := "notice"
	phone := 18888888888
	otpstr := "127892"

	var number = gosms.NoCodePhoneNumber(phone)
	var gateway = ywxt.GateWay(string(appName), string(appSecret), string(smsHost), string(sendUrl), string(tokenUrl))

	var message = gosms.MessageTemplate(string(templateId), gosms.MapStrings{
		"notice": fmt.Sprintf(string(notice), otpstr),
		//"notice": fmt.Sprintf("您的验证码为：%s，请于5分钟内正确输入，如非本人操作，请忽略此短信", otpstr),
	})
	result, err := gosms.Sender(number, message, gateway)
	if resp, ok := result.ClientResult.Response.(ywxt.Response); ok {
		fmt.Println(resp)
	}
	fmt.Println(err)
}
