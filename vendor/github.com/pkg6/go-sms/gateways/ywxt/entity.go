package ywxt

type Response struct {
	Code int `json:"code"`
	Data struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
		MsgId   string `json:"msgId"`
	} `json:"data"`
	Msg string `json:"msg"`
}
type PostBody struct {
	SmsTemplateCode string      `json:"smsTemplateCode"`
	PhoneNumbers    PhoneNumber `json:"phoneNumbers"`
	ParamJson       Param       `json:"paramJson"`
}

type PhoneNumber []string
type Param struct {
	Notice  string `json:"notice"`
	AppName string `json:"appName"`
}
