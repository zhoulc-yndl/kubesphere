package ywxt

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pkg6/go-sms"
	"io"
	"log"
)

type Ywxt struct {
	Host       string `json:"host" xml:"host"`
	AppSecret  string `json:"appSecret"`
	SendUrl    string `json:"sendUrl"`
	TemplateId string `json:"templateId"`
	TokenUrl   string `json:"tokenUrl"`
	AppName    string `json:"appName"`
	Format     string `json:"format" xml:"format"`
	gosms.Lock
}

func GateWay(appName, appSecret,host,sendUrl,tokenUrl string) gosms.IGateway {
	gateway := &Ywxt{
		AppName:   appName,
		AppSecret: appSecret,
	}
	return gateway.I()
}
func (g Ywxt) I() gosms.IGateway {
	if g.Host == "" {
		g.Host = "https://ythbgptuat.ywxt.sh.gov.cn/api-gateway/uranus/uranus/cgi-bin"
	}
	if g.SendUrl == "" {
		g.SendUrl = "request/sms/template/send"
	}
	if g.TokenUrl == "" {
		g.TokenUrl = "gettoken"
	}
	if g.Format == "" {
		g.Format = "JSON"
	}
	g.LockInit()
	return &g
}

func (g *Ywxt) AsName() string {
	return "ywxt"
}

// 请求参数生成
func (g *Ywxt) query() gosms.MapStrings {

	if g.Format == "" {
		g.Format = "JSON"
	}
	maps := gosms.MapStrings{
		"AppSecret": g.AppSecret,
		"Action":    "SendSms",
		"Format":    g.Format,
	}
	return maps
}

func (g *Ywxt) getAccessToken(appSecret string) string {
	query := g.query()
	query["corpsecret"] = appSecret
	res, err := gosms.Client.Get(context.Background(), g.Host+"/"+g.TokenUrl, query)

	//res, err := http.Get(string(tokenUrl) + "?corpsecret=" + string(appSecret))
	if err != nil {
		log.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode > 299 {
		log.Fatal(body)
	}
	if err != nil {
		log.Fatal(err)

	}
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Fatal(err)
	}
	errCode, ok := result["errcode"].(float64)
	if errCode != 0 {
		log.Fatal(ok)
	}
	accessToken, ok := result["access_token"].(string)
	if !ok {
		log.Fatal(ok)
	}
	return accessToken
}

func (g *Ywxt) Send(to gosms.IPhoneNumber, message gosms.IMessage) (gosms.SMSResult, error) {
	g.Lock.L.Lock()
	defer g.L.Unlock()
	var resp Response
	data := message.GetData(g.I())
	notice := data.GetDefault("notice", "")
	mobile := gosms.GetPhoneNumber(to)

	var phoneNumbers = PhoneNumber{mobile}
	templateId := message.GetTemplate(g.I())
	// 发送短信
	postBody := &PostBody{
		SmsTemplateCode: templateId,
		PhoneNumbers:    phoneNumbers,
		ParamJson: Param{
			Notice:  notice,
			AppName: g.AppName,
		},
	}

	accessToken := g.getAccessToken(g.AppSecret)
	client := gosms.Client
	client.WithHeader("Content-Type", "application/json")
	response, err := client.PostJson(context.Background(), g.Host+"/"+g.SendUrl+"?access_token="+accessToken, postBody)
	err = response.Unmarshal(&resp)
	result := gosms.BuildSMSResult(to, message, g.I(), resp)
	if err != nil {
		return result, err
	}
	if resp.Code != 200 {
		return result, errors.New(resp.Msg)
	}
	return result, err

}
