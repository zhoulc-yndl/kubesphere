/*

 Copyright 2021 The KubeSphere Authors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"github.com/emicklei/go-restful"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"image/png"
	"io"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog"
	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
	kubesphere "kubesphere.io/kubesphere/pkg/client/clientset/versioned"
	iamv1alpha2listers "kubesphere.io/kubesphere/pkg/client/listers/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/constants"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type passcodeAuthenticator struct {
	ksClient    kubesphere.Interface
	userGetter  *userGetter
	authOptions *authentication.Options
}

func NewPasscodeAuthenticator(ksClient kubesphere.Interface,
	userLister iamv1alpha2listers.UserLister,
	options *authentication.Options) PasscodeAuthenticator {
	passcodeAuthenticator := &passcodeAuthenticator{
		ksClient:    ksClient,
		userGetter:  &userGetter{userLister: userLister},
		authOptions: options,
	}
	return passcodeAuthenticator
}

func (p *passcodeAuthenticator) Authenticate(ctx context.Context, username, password string, passcode string) (authuser.Info, string, error) {
	// empty username or password are not allowed
	if username == "" || password == "" {
		return nil, "", IncorrectPasswordError
	}

	// generic identity provider has higher priority
	for _, providerOptions := range p.authOptions.OAuthOptions.IdentityProviders {
		// the admin account in kubesphere has the highest priority
		if username == constants.AdminUserName {
			break
		}
		if genericProvider, _ := identityprovider.GetGenericProvider(providerOptions.Name); genericProvider != nil {
			authenticated, err := genericProvider.Authenticate(username, password)
			if err != nil {
				if errors.IsUnauthorized(err) {
					continue
				}
				return nil, providerOptions.Name, err
			}
			linkedAccount, err := p.userGetter.findMappedUser(providerOptions.Name, authenticated.GetUserID())
			if err != nil && !errors.IsNotFound(err) {
				klog.Error(err)
				return nil, providerOptions.Name, err
			}
			// using this method requires you to manually provision users.
			if providerOptions.MappingMethod == oauth.MappingMethodLookup && linkedAccount == nil {
				continue
			}
			// the user will automatically create and mapping when login successful.
			if linkedAccount == nil && providerOptions.MappingMethod == oauth.MappingMethodAuto {
				if !providerOptions.DisableLoginConfirmation {
					return preRegistrationUser(providerOptions.Name, authenticated), providerOptions.Name, nil
				}

				linkedAccount, err = p.ksClient.IamV1alpha2().Users().Create(context.Background(), mappedUser(providerOptions.Name, authenticated), metav1.CreateOptions{})
				if err != nil {
					return nil, providerOptions.Name, err
				}
			}
			if linkedAccount != nil {
				return &authuser.DefaultInfo{Name: linkedAccount.GetName()}, providerOptions.Name, nil
			}
		}
	}

	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {
		// ignore not found error
		if !errors.IsNotFound(err) {
			klog.Error(err)
			return nil, "", err
		}
	}

	// check user status
	if user != nil && user.Status.State != iamv1alpha2.UserActive {
		if user.Status.State == iamv1alpha2.UserAuthLimitExceeded {
			klog.Errorf("%s, username: %s", RateLimitExceededError, username)
			return nil, "", RateLimitExceededError
		} else {
			// state not active
			klog.Errorf("%s, username: %s", AccountIsNotActiveError, username)
			return nil, "", AccountIsNotActiveError
		}
	}

	// check user 2fa status
	if user != nil && user.Spec.FAOpenStatus && passcode == "" {
		u := &authuser.DefaultInfo{
			Name:   user.Name,
			Groups: user.Spec.Groups,
		}
		u.Extra = map[string][]string{
			iamv1alpha2.ExtraFAOpenStatus: {strconv.FormatBool(user.Spec.FAOpenStatus)},
			iamv1alpha2.ExtraFAType:       {user.Spec.FAType},
			iamv1alpha2.ExtraOTPBind:      {strconv.FormatBool(user.Spec.OTPBind)},
		}

		return u, "", nil
	}
	//OTP Verify
	if user != nil && user.Spec.FAOpenStatus && user.Spec.OTPBind && user.Spec.FAType == iamv1alpha2.FATypeOtp {
		otpKey, _ := otp.NewKeyFromURL(user.Spec.OTPKey.Orig)
		if user.Spec.OTPKey != nil && !totp.Validate(passcode, otpKey.Secret(), uint(otpKey.Period())) {
			return nil, "", IncorrectOtpError
		}
		// update otp bind status
		user.Spec.OTPBind = true
		_, err = p.ksClient.IamV1alpha2().Users().Update(ctx, user, metav1.UpdateOptions{})
		if err != nil {
			klog.Error(err)
			return nil, "", err
		}
	}

	// SMS Verify
	if user != nil && user.Spec.FAOpenStatus && user.Spec.FAType == iamv1alpha2.FATypeSms {
		smsKey, _ := otp.NewKeyFromURL(user.Spec.SMSKey.Orig)
		if user.Spec.SMSKey != nil && !totp.Validate(passcode, smsKey.Secret(), uint(smsKey.Period())) {
			return nil, "", IncorrectSmsError
		}
	}
	// if the password is not empty, means that the password has been reset, even if the user was mapping from IDP
	if user != nil && user.Spec.EncryptedPassword != "" {
		if err = PasswordVerify(user.Spec.EncryptedPassword, password); err != nil {
			klog.Error(err)
			return nil, "", err
		}
		u := &authuser.DefaultInfo{
			Name:   user.Name,
			Groups: user.Spec.Groups,
		}
		// check if the password is initialized
		if uninitialized := user.Annotations[iamv1alpha2.UninitializedAnnotation]; uninitialized != "" {
			u.Extra = map[string][]string{
				iamv1alpha2.ExtraUninitialized: {uninitialized},
			}
		}

		return u, "", nil
	}

	return nil, "", IncorrectPasswordError
}

func (p *passcodeAuthenticator) Enable2fa(req *restful.Request, response *restful.Response, username, issuer, faType, global string) {

	// global set
	if global == "true" {
		userList, err := p.ksClient.IamV1alpha2().Users().List(req.Request.Context(), metav1.ListOptions{})
		if err != nil {
			klog.Error(err)
		}
		for _, item := range userList.Items {
			if !item.Spec.FAOpenStatus {
				p.set2faOpen(req, response, item.DeepCopy(), issuer, faType)
			}
		}
	} else {
		// kubesphere account
		user, err := p.userGetter.findUser(username)
		if err != nil {
			// ignore not found error
			if !errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil {
			p.set2faOpen(req, response, user, issuer, faType)
		}

	}

}

func (p *passcodeAuthenticator) set2faOpen(request *restful.Request, response *restful.Response, user *iamv1alpha2.User, issuer, faType string) {

	if faType == iamv1alpha2.FATypeOtp {
		// 如果不存在OTPKey，则更新
		if user.Spec.OTPKey == nil || user.Spec.OTPKey.Orig == "" {
			// 生成 TOTP 密钥配置
			opts := totp.GenerateOpts{
				Issuer:      issuer,
				AccountName: user.Name,
				SecretSize:  20,
			}

			secret := make([]byte, opts.SecretSize)
			_, err := rand.Reader.Read(secret)
			if err != nil {
				panic(err)
			}
			opts.Secret = secret
			key, err := totp.Generate(opts)
			if err != nil {
				panic(err)
			}
			u, _ := url.Parse(key.String())
			us := u.User
			otpUsername := us.Username()
			otpPassword, otpPasswordSet := us.Password()
			b := &iamv1alpha2.OtpKey{
				Orig: key.String(),
				Url: &iamv1alpha2.OtpURL{
					Scheme: u.Scheme,
					Opaque: u.Opaque,
					User: &iamv1alpha2.OtpUrlUserinfo{
						Username:    otpUsername,
						Password:    otpPassword,
						PasswordSet: otpPasswordSet,
					},
					Host:        u.Host,
					Path:        u.Path,
					RawPath:     u.RawPath,
					OmitHost:    u.OmitHost,
					ForceQuery:  u.ForceQuery,
					RawQuery:    u.RawQuery,
					Fragment:    u.Fragment,
					RawFragment: u.RawFragment,
				},
			}
			user.Spec.OTPKey = b
		}

		// update user set 2fa open status and otpKey info
		user.Spec.FAOpenStatus = true
		user.Spec.FAType = iamv1alpha2.FATypeOtp
	}
	if faType == iamv1alpha2.FATypeSms {
		if user.Spec.Phone != "" {
			// 使用otp生成短信验证码
			if user.Spec.SMSKey == nil || user.Spec.SMSKey.Orig == "" {
				// 生成 TOTP 密钥配置
				opts := totp.GenerateOpts{
					Issuer:      "sms",
					AccountName: user.Name,
					SecretSize:  20,
					Period:      300,
				}

				secret := make([]byte, opts.SecretSize)
				_, err := rand.Reader.Read(secret)
				if err != nil {
					panic(err)
				}
				opts.Secret = secret
				key, err := totp.Generate(opts)
				if err != nil {
					panic(err)
				}
				u, _ := url.Parse(key.String())
				us := u.User
				otpUsername := us.Username()
				otpPassword, otpPasswordSet := us.Password()
				b := &iamv1alpha2.OtpKey{
					Orig: key.String(),
					Url: &iamv1alpha2.OtpURL{
						Scheme: u.Scheme,
						Opaque: u.Opaque,
						User: &iamv1alpha2.OtpUrlUserinfo{
							Username:    otpUsername,
							Password:    otpPassword,
							PasswordSet: otpPasswordSet,
						},
						Host:        u.Host,
						Path:        u.Path,
						RawPath:     u.RawPath,
						OmitHost:    u.OmitHost,
						ForceQuery:  u.ForceQuery,
						RawQuery:    u.RawQuery,
						Fragment:    u.Fragment,
						RawFragment: u.RawFragment,
					},
				}
				user.Spec.SMSKey = b
			}
			user.Spec.FAOpenStatus = true
			user.Spec.FAType = iamv1alpha2.FATypeSms
		}
	}
	_, err := p.ksClient.IamV1alpha2().Users().Update(request.Request.Context(), user, metav1.UpdateOptions{})
	if err != nil {
		klog.Error(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, "ok")
}

func (p *passcodeAuthenticator) Disable2fa(req *restful.Request, response *restful.Response, username, global string) {

	// global set
	if global == "true" {
		userList, err := p.ksClient.IamV1alpha2().Users().List(req.Request.Context(), metav1.ListOptions{})
		if err != nil {
			klog.Error(err)
		}
		for _, item := range userList.Items {
			if item.Spec.FAOpenStatus {
				item.Spec.FAOpenStatus = false
				_, err = p.ksClient.IamV1alpha2().Users().Update(req.Request.Context(), item.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					klog.Error(err)
					response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
					return
				}
			}
		}
	} else {
		// kubesphere account
		user, err := p.userGetter.findUser(username)
		if err != nil {
			// ignore not found error
			if !errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil && user.Spec.FAOpenStatus {
			user.Spec.FAOpenStatus = false
			_, err = p.ksClient.IamV1alpha2().Users().Update(req.Request.Context(), user.DeepCopy(), metav1.UpdateOptions{})
			if err != nil {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
	}
	response.WriteHeaderAndEntity(http.StatusOK, "ok")
}

func (p *passcodeAuthenticator) ResetOTP(req *restful.Request, response *restful.Response, username, issuer string) {
	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {
		// ignore not found error
		if !errors.IsNotFound(err) {
			klog.Error(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
			return
		}
	}
	// 生成 TOTP 密钥配置
	opts := totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Name,
		SecretSize:  20,
	}

	secret := make([]byte, opts.SecretSize)
	_, err = rand.Reader.Read(secret)
	if err != nil {
		panic(err)
	}
	opts.Secret = secret
	key, err := totp.Generate(opts)
	if err != nil {
		panic(err)
	}
	u, _ := url.Parse(key.String())
	us := u.User
	otpUsername := us.Username()
	otpPassword, otpPasswordSet := us.Password()
	b := &iamv1alpha2.OtpKey{
		Orig: key.String(),
		Url: &iamv1alpha2.OtpURL{
			Scheme: u.Scheme,
			Opaque: u.Opaque,
			User: &iamv1alpha2.OtpUrlUserinfo{
				Username:    otpUsername,
				Password:    otpPassword,
				PasswordSet: otpPasswordSet,
			},
			Host:        u.Host,
			Path:        u.Path,
			RawPath:     u.RawPath,
			OmitHost:    u.OmitHost,
			ForceQuery:  u.ForceQuery,
			RawQuery:    u.RawQuery,
			Fragment:    u.Fragment,
			RawFragment: u.RawFragment,
		},
	}
	user.Spec.OTPKey = b

	// update user set 2fa open status and otpKey info
	user.Spec.FAOpenStatus = true
	user.Spec.OTPBind = false
	_, err = p.ksClient.IamV1alpha2().Users().Update(req.Request.Context(), user, metav1.UpdateOptions{})
	if err != nil {
		klog.Error(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
	response.WriteHeaderAndEntity(http.StatusOK, "ok")
}

func (p *passcodeAuthenticator) OtpBarcode(request *restful.Request, response *restful.Response, username string) {

	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {
		// ignore not found error
		if !errors.IsNotFound(err) {
			klog.Error(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
			return
		}
	}
	if user.Spec.FAType != iamv1alpha2.FATypeOtp {
		klog.Error(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, "current 2fa type is not otp")
		return
	}
	otpKey, _ := otp.NewKeyFromURL(user.Spec.OTPKey.Orig)
	//Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := otpKey.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	response.Header().Set("Content-Type", "image/png")
	response.Write(buf.Bytes())
}

func (p *passcodeAuthenticator) SendMessage(request *restful.Request, response *restful.Response, username string, secret runtime.Object) {

	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {
		// ignore not found error
		if !errors.IsNotFound(err) {
			klog.Error(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
			return
		}
	}
	phone := user.Spec.Phone
	smsKey, _ := otp.NewKeyFromURL(user.Spec.SMSKey.Orig)
	smsOtpSecret := smsKey.Secret()
	var smsSecret *v1.Secret
	smsSecret = secret.(*v1.Secret)
	appSecret := smsSecret.Data["Secret"]
	sendUrl := smsSecret.Data["sendUrl"]
	templateId := smsSecret.Data["templateId"]
	tokenUrl := smsSecret.Data["tokenUrl"]
	// 获取ywxt的access_token
	res, err := http.Get(string(tokenUrl) + "?corpsecret=" + string(appSecret))
	if err != nil {
		log.Fatal(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode > 299 {
		response.WriteHeaderAndEntity(res.StatusCode, body)
		return
	}
	if err != nil {
		log.Fatal(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Fatal(err)
	}
	errCode, ok := result["errcode"].(float64)
	if errCode != 0 {
		response.WriteHeaderAndEntity(http.StatusBadRequest, result["errmsg"])
		return
	}
	accessToken, ok := result["access_token"].(string)
	if !ok {
		response.WriteHeaderAndEntity(http.StatusBadRequest, "get access_token error")
		return
	}
	// 使用otp生成验证码，300s有效期
	t := time.Now().UTC()
	counter := int64(math.Floor(float64(t.Unix()) / float64(300)))
	otpstr, err := hotp.GenerateCodeCustom(smsOtpSecret, uint64(counter), hotp.ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusBadRequest, "sms passcode genera error")
		return
	}
	// 发送短信
	postBody := strings.NewReader(`{"smsTemplateCode":"` + string(templateId) + `","phoneNumbers":["` + phone + `"],"paramJson":{"notice": "您的验证码为` + otpstr + `，请于5分钟内正确输入，如非本人操作，请忽略此短信。","appName": "SWIFT云平台"}}`)
	resp, err := http.Post(
		string(sendUrl)+"?access_token="+string(accessToken),
		"application/json",
		postBody,
	)
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// 打印响应
	println(string(respBody))
	var sendRes map[string]interface{}
	err = json.Unmarshal(respBody, &sendRes)
	if err != nil {
		log.Fatal(err)
	}
	response.WriteHeaderAndEntity(http.StatusOK, sendRes)
}

// IsAdmin 检查用户是否是管理员的函数
func (p *passcodeAuthenticator) IsAdmin(username string) bool {
	adminClusterRole := "platform-admin"
	adminRoleBindingLister, err := p.ksClient.IamV1alpha2().GlobalRoleBindings().List(context.TODO(), metav1.ListOptions{})
	//informer := ksinformers.NewSharedInformerFactory(p.ksClient, 0)
	//adminRoleBindingLister := informer.Iam().V1alpha2().GlobalRoleBindings().Lister()
	//roleBindings, err := adminRoleBindingLister.List(labels.Everything())
	if err != nil {
		// 处理错误，例如记录日志
		return false
	}

	for _, roleBinding := range adminRoleBindingLister.Items {
		if roleBinding.RoleRef.Kind == iamv1alpha2.ResourceKindGlobalRole && roleBinding.RoleRef.Name == adminClusterRole {
			for _, subject := range roleBinding.Subjects {
				if subject.Kind == iamv1alpha2.ResourceKindUser && subject.Name == username {
					return true
				}
			}
		}
	}

	return false
}

func (p *passcodeAuthenticator) EnableOTP(req *restful.Request, response *restful.Response, username, issuer string, global string) {

	// global set
	if global == "true" {
		userList, err := p.ksClient.IamV1alpha2().Users().List(req.Request.Context(), metav1.ListOptions{})
		if err != nil {
			klog.Error(err)
		}
		for _, item := range userList.Items {
			if !item.Spec.FAOpenStatus {
				p.setOtpOpen(req, response, item.DeepCopy(), issuer)
			}
		}
	} else {
		// kubesphere account
		user, err := p.userGetter.findUser(username)
		if err != nil {
			// ignore not found error
			if !errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil && !user.Spec.FAOpenStatus {
			p.setOtpOpen(req, response, user, issuer)
		}

	}

}

func (p *passcodeAuthenticator) setOtpOpen(request *restful.Request, response *restful.Response, user *iamv1alpha2.User, issuer string) {

	// 如果不存在OTPKey，则更新
	if user.Spec.OTPKey.Orig == "" {
		// 生成 TOTP 密钥配置
		opts := totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: user.Name,
			SecretSize:  20,
		}

		secret := make([]byte, opts.SecretSize)
		_, err := rand.Reader.Read(secret)
		if err != nil {
			panic(err)
		}
		opts.Secret = secret
		key, err := totp.Generate(opts)
		if err != nil {
			panic(err)
		}
		u, _ := url.Parse(key.String())
		us := u.User
		otpUsername := us.Username()
		otpPassword, otpPasswordSet := us.Password()
		b := &iamv1alpha2.OtpKey{
			Orig: key.String(),
			Url: &iamv1alpha2.OtpURL{
				Scheme: u.Scheme,
				Opaque: u.Opaque,
				User: &iamv1alpha2.OtpUrlUserinfo{
					Username:    otpUsername,
					Password:    otpPassword,
					PasswordSet: otpPasswordSet,
				},
				Host:        u.Host,
				Path:        u.Path,
				RawPath:     u.RawPath,
				OmitHost:    u.OmitHost,
				ForceQuery:  u.ForceQuery,
				RawQuery:    u.RawQuery,
				Fragment:    u.Fragment,
				RawFragment: u.RawFragment,
			},
		}
		user.Spec.OTPKey = b
	}

	// update user set 2fa open status and otpKey info
	user.Spec.FAOpenStatus = true
	user.Spec.FAType = iamv1alpha2.FATypeOtp
	//user.Spec.OTPBind = true
	_, err := p.ksClient.IamV1alpha2().Users().Update(request.Request.Context(), user, metav1.UpdateOptions{})
	if err != nil {
		klog.Error(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
		return
	}
}

func (p *passcodeAuthenticator) EnableSMS(request *restful.Request, response *restful.Response, username string, global string) {

	// global set
	if global == "true" {
		userList, err := p.ksClient.IamV1alpha2().Users().List(request.Request.Context(), metav1.ListOptions{})
		if err != nil {
			klog.Error(err)
		}
		for _, item := range userList.Items {
			if !item.Spec.FAOpenStatus {
				p.setSmsOpen(request, response, item.DeepCopy())
			}
		}
	} else {
		// kubesphere account
		user, err := p.userGetter.findUser(username)
		if err != nil {
			// ignore not found error
			if !errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil && !user.Spec.FAOpenStatus {
			p.setSmsOpen(request, response, user)
		}

	}

}

func (p *passcodeAuthenticator) setSmsOpen(request *restful.Request, response *restful.Response, user *iamv1alpha2.User) {
	if user.Spec.Phone != "" {
		// 使用otp生成短信验证码
		if user.Spec.SMSKey.Orig == "" {
			// 生成 TOTP 密钥配置
			opts := totp.GenerateOpts{
				Issuer:      "sms",
				AccountName: user.Name,
				SecretSize:  20,
				Period:      300,
			}

			secret := make([]byte, opts.SecretSize)
			_, err := rand.Reader.Read(secret)
			if err != nil {
				panic(err)
			}
			opts.Secret = secret
			key, err := totp.Generate(opts)
			if err != nil {
				panic(err)
			}
			u, _ := url.Parse(key.String())
			us := u.User
			otpUsername := us.Username()
			otpPassword, otpPasswordSet := us.Password()
			b := &iamv1alpha2.OtpKey{
				Orig: key.String(),
				Url: &iamv1alpha2.OtpURL{
					Scheme: u.Scheme,
					Opaque: u.Opaque,
					User: &iamv1alpha2.OtpUrlUserinfo{
						Username:    otpUsername,
						Password:    otpPassword,
						PasswordSet: otpPasswordSet,
					},
					Host:        u.Host,
					Path:        u.Path,
					RawPath:     u.RawPath,
					OmitHost:    u.OmitHost,
					ForceQuery:  u.ForceQuery,
					RawQuery:    u.RawQuery,
					Fragment:    u.Fragment,
					RawFragment: u.RawFragment,
				},
			}
			user.Spec.SMSKey = b
		}
		user.Spec.FAOpenStatus = true
		user.Spec.FAType = iamv1alpha2.FATypeSms
		_, err := p.ksClient.IamV1alpha2().Users().Update(request.Request.Context(), user, metav1.UpdateOptions{})
		if err != nil {
			klog.Error(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
			return
		}
	}
}
