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
	"encoding/base32"
	"fmt"
	"github.com/emicklei/go-restful"
	gosms "github.com/pkg6/go-sms"
	"github.com/pkg6/go-sms/gateways/aliyun"
	"github.com/pkg6/go-sms/gateways/ihuyi"
	"github.com/pkg6/go-sms/gateways/juhe"
	"github.com/pkg6/go-sms/gateways/lmobile"
	"github.com/pkg6/go-sms/gateways/smsbao"
	"github.com/pkg6/go-sms/gateways/yunxin"
	"github.com/pkg6/go-sms/gateways/ywxt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"gopkg.in/yaml.v2"
	"image/png"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	iamv1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
	"kubesphere.io/kubesphere/pkg/apiserver/config"
	kubesphere "kubesphere.io/kubesphere/pkg/client/clientset/versioned"
	iamv1alpha2listers "kubesphere.io/kubesphere/pkg/client/listers/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/simple/client/multiauth"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type passcodeAuthenticator struct {
	ksClient    kubesphere.Interface
	userGetter  *userGetter
	authOptions *authentication.Options
	k8sClient   kubernetes.Interface
}

func NewPasscodeAuthenticator(ksClient kubesphere.Interface,
	userLister iamv1alpha2listers.UserLister,
	options *authentication.Options,
	k8sClient kubernetes.Interface) PasscodeAuthenticator {
	passcodeAuthenticator := &passcodeAuthenticator{
		ksClient:    ksClient,
		userGetter:  &userGetter{userLister: userLister},
		authOptions: options,
		k8sClient:   k8sClient,
	}
	return passcodeAuthenticator
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

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
		if errors.IsNotFound(err) {
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

	// if the password is not empty, means that the password has been reset, even if the user was mapping from IDP
	if user != nil && user.Spec.EncryptedPassword != "" {
		if err = PasswordVerify(user.Spec.EncryptedPassword, password); err != nil {
			klog.Error(err)
			return nil, "", err
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
		if user != nil && user.Spec.FAOpenStatus && user.Spec.FAType == iamv1alpha2.FATypeOtp {
			orig, _ := b32NoPadding.DecodeString(user.Spec.OTPKey.Orig)
			otpKey, _ := otp.NewKeyFromURL(string(orig))
			if user.Spec.OTPKey != nil && !totp.Validate(passcode, otpKey.Secret(), uint(otpKey.Period())) {
				return nil, "", IncorrectOtpError
			}
			if !user.Spec.OTPBind {
				// update otp bind status
				user.Spec.OTPBind = true
				_, err = p.ksClient.IamV1alpha2().Users().Update(ctx, user, metav1.UpdateOptions{})
				if err != nil {
					klog.Error(err)
					return nil, "", err
				}
			}

		}

		// SMS Verify
		if user != nil && user.Spec.FAOpenStatus && user.Spec.FAType == iamv1alpha2.FATypeSms {
			orig, _ := b32NoPadding.DecodeString(user.Spec.SMSKey.Orig)
			smsKey, _ := otp.NewKeyFromURL(string(orig))
			if user.Spec.SMSKey != nil && !totp.Validate(passcode, smsKey.Secret(), uint(smsKey.Period())) {
				return nil, "", IncorrectSmsError
			}
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
		cm, err := p.k8sClient.CoreV1().ConfigMaps(constants.KubeSphereNamespace).Get(context.TODO(), constants.KubeSphereMultauthConfigName, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
		}

		configData := &config.Config{}
		value, ok := cm.Data[constants.KubeSphereMultauthConfigMapDataKey]
		if !ok {
			klog.Error(fmt.Errorf("failed to get configmap multauth-config.yaml value"))
			response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to get configmap multauth-config.yaml value"))
			return
		}
		if err := yaml.Unmarshal([]byte(value), configData); err != nil {
			klog.Error(fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
			response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
			return
		}

		if err != nil {
			klog.Error(err)
		}
		if configData.MultiauthOptions == nil {
			configData.MultiauthOptions = &multiauth.Options{}
		}
		configData.MultiauthOptions.FAOpenStatus = true
		configData.MultiauthOptions.FAType = faType
		configData.MultiauthOptions.Issuer = issuer

		newConfigData, err := yaml.Marshal(configData)
		if err != nil {
			klog.Error(err)
		}
		cm.Data[constants.KubeSphereMultauthConfigMapDataKey] = string(newConfigData)
		p.k8sClient.CoreV1().ConfigMaps(constants.KubeSphereNamespace).Update(req.Request.Context(), cm, metav1.UpdateOptions{})
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
			if errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil {
			p.set2faOpen(req, response, user, issuer, faType)
		}

	}
	ok := map[string]string{
		"Msg": "ok",
	}
	response.WriteHeaderAndEntity(http.StatusOK, ok)

}

func (p *passcodeAuthenticator) set2faOpen(request *restful.Request, response *restful.Response, user *iamv1alpha2.User, issuer, faType string) {

	if faType == iamv1alpha2.FATypeOtp {
		// 如果不存在OTPKey，则更新
		if user.Spec.OTPKey == nil || user.Spec.OTPKey.Orig == "" {
			if issuer == "" {
				err := fmt.Errorf("otp issuer is null")
				api.HandleBadRequest(response, request, err)
				return
			}
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
				Orig: b32NoPadding.EncodeToString([]byte(key.String())),
				Url: &iamv1alpha2.OtpURL{
					Scheme: u.Scheme,
					Opaque: u.Opaque,
					User: &iamv1alpha2.OtpUrlUserinfo{
						Username:    b32NoPadding.EncodeToString([]byte(otpUsername)),
						Password:    b32NoPadding.EncodeToString([]byte(otpPassword)),
						PasswordSet: otpPasswordSet,
					},
					Host:        b32NoPadding.EncodeToString([]byte(u.Host)),
					Path:        b32NoPadding.EncodeToString([]byte(u.Path)),
					RawPath:     b32NoPadding.EncodeToString([]byte(u.RawPath)),
					OmitHost:    u.OmitHost,
					ForceQuery:  u.ForceQuery,
					RawQuery:    b32NoPadding.EncodeToString([]byte(u.RawQuery)),
					Fragment:    b32NoPadding.EncodeToString([]byte(u.Fragment)),
					RawFragment: b32NoPadding.EncodeToString([]byte(u.RawFragment)),
				},
			}
			user.Spec.OTPKey = b
		}

		// update user set 2fa open status and otpKey info
		user.Spec.FAOpenStatus = true
		user.Spec.FAType = iamv1alpha2.FATypeOtp
		user.Spec.Issuer = issuer
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
					Orig: b32NoPadding.EncodeToString([]byte(key.String())),
					Url: &iamv1alpha2.OtpURL{
						Scheme: u.Scheme,
						Opaque: u.Opaque,
						User: &iamv1alpha2.OtpUrlUserinfo{
							Username:    b32NoPadding.EncodeToString([]byte(otpUsername)),
							Password:    b32NoPadding.EncodeToString([]byte(otpPassword)),
							PasswordSet: otpPasswordSet,
						},
						Host:        b32NoPadding.EncodeToString([]byte(u.Host)),
						Path:        b32NoPadding.EncodeToString([]byte(u.Path)),
						RawPath:     b32NoPadding.EncodeToString([]byte(u.RawPath)),
						OmitHost:    u.OmitHost,
						ForceQuery:  u.ForceQuery,
						RawQuery:    b32NoPadding.EncodeToString([]byte(u.RawQuery)),
						Fragment:    b32NoPadding.EncodeToString([]byte(u.Fragment)),
						RawFragment: b32NoPadding.EncodeToString([]byte(u.RawFragment)),
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

}

func (p *passcodeAuthenticator) Disable2fa(req *restful.Request, response *restful.Response, username, global string) {

	// global set
	if global == "true" {
		cm, err := p.k8sClient.CoreV1().ConfigMaps(constants.KubeSphereNamespace).Get(context.TODO(), constants.KubeSphereMultauthConfigName, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
		}

		configData := &config.Config{}
		value, ok := cm.Data[constants.KubeSphereMultauthConfigMapDataKey]
		if !ok {
			klog.Error(fmt.Errorf("failed to get configmap multauth-config.yaml value"))
			response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to get configmap multauth-config.yaml value"))
			return
		}
		if err := yaml.Unmarshal([]byte(value), configData); err != nil {
			klog.Error(fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
			response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
			return
		}

		if err != nil {
			klog.Error(err)
		}
		if configData.MultiauthOptions == nil {
			configData.MultiauthOptions = &multiauth.Options{}
		}
		configData.MultiauthOptions.FAOpenStatus = false

		newConfigData, err := yaml.Marshal(configData)
		if err != nil {
			klog.Error(err)
		}
		cm.Data[constants.KubeSphereMultauthConfigMapDataKey] = string(newConfigData)
		p.k8sClient.CoreV1().ConfigMaps(constants.KubeSphereNamespace).Update(req.Request.Context(), cm, metav1.UpdateOptions{})
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
			if errors.IsNotFound(err) {
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
	ok := map[string]string{
		"Msg": "ok",
	}
	response.WriteHeaderAndEntity(http.StatusOK, ok)
}

func (p *passcodeAuthenticator) ResetOTP(req *restful.Request, response *restful.Response, username, issuer string) {
	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {

		if errors.IsNotFound(err) {
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
		Orig: b32NoPadding.EncodeToString([]byte(key.String())),
		Url: &iamv1alpha2.OtpURL{
			Scheme: u.Scheme,
			Opaque: u.Opaque,
			User: &iamv1alpha2.OtpUrlUserinfo{
				Username:    b32NoPadding.EncodeToString([]byte(otpUsername)),
				Password:    b32NoPadding.EncodeToString([]byte(otpPassword)),
				PasswordSet: otpPasswordSet,
			},
			Host:        b32NoPadding.EncodeToString([]byte(u.Host)),
			Path:        b32NoPadding.EncodeToString([]byte(u.Path)),
			RawPath:     b32NoPadding.EncodeToString([]byte(u.RawPath)),
			OmitHost:    u.OmitHost,
			ForceQuery:  u.ForceQuery,
			RawQuery:    b32NoPadding.EncodeToString([]byte(u.RawQuery)),
			Fragment:    b32NoPadding.EncodeToString([]byte(u.Fragment)),
			RawFragment: b32NoPadding.EncodeToString([]byte(u.RawFragment)),
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
	ok := map[string]string{
		"Msg": "ok",
	}
	response.WriteHeaderAndEntity(http.StatusOK, ok)
}

func (p *passcodeAuthenticator) OtpBarcode(request *restful.Request, response *restful.Response, username string) {

	// kubesphere account
	user, err := p.userGetter.findUser(username)
	if err != nil {

		if errors.IsNotFound(err) {
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
	orig, _ := b32NoPadding.DecodeString(user.Spec.OTPKey.Orig)
	otpKey, _ := otp.NewKeyFromURL(string(orig))
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

		if errors.IsNotFound(err) {
			klog.Error(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
			return
		}
	}

	phone, err := strconv.Atoi(user.Spec.Phone)
	if err != nil {
		log.Fatal(err)
		response.WriteHeaderAndEntity(http.StatusBadRequest, "invalid phone number")
		return
	}
	orig, _ := b32NoPadding.DecodeString(user.Spec.SMSKey.Orig)
	smsKey, _ := otp.NewKeyFromURL(string(orig))
	smsOtpSecret := smsKey.Secret()
	var smsSecret *v1.Secret
	smsSecret = secret.(*v1.Secret)
	// 使用otp生成验证码，300s有效期
	t := time.Now().UTC()
	counter := int64(math.Floor(float64(t.Unix()) / float64(300)))
	otpstr, err := hotp.GenerateCodeCustom(smsOtpSecret, uint64(counter), hotp.ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	smsServiceProvider := string(smsSecret.Data["serviceProvider"])
	switch smsServiceProvider {
	case "ywxt":
		appSecret := smsSecret.Data["Secret"]
		sendUrl := smsSecret.Data["sendUrl"]
		templateId := smsSecret.Data["templateId"]
		tokenUrl := smsSecret.Data["tokenUrl"]
		appName := smsSecret.Data["appName"]
		smsHost := smsSecret.Data["host"]
		notice := smsSecret.Data["notice"]

		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = ywxt.GateWay(string(appName), string(appSecret), string(smsHost), string(sendUrl), string(tokenUrl))

		var message = gosms.MessageTemplate(string(templateId), gosms.MapStrings{
			"notice": fmt.Sprintf(string(notice), otpstr),
			//"notice": fmt.Sprintf("您的验证码为：%s，请于5分钟内正确输入，如非本人操作，请忽略此短信", otpstr),
		})
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(ywxt.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, resp.Msg)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	互亿无线
	case "ihuiyi":
		account := string(smsSecret.Data["account"])
		password := string(smsSecret.Data["password"])
		notice := string(smsSecret.Data["notice"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = ihuyi.GateWay(account, password)
		//var message = gosms.MessageContent("您的验证码是：****。请不要把验证码泄露给其他人。")
		var message = gosms.MessageContent(fmt.Sprintf(notice, otpstr))
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(ihuyi.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, resp.Msg)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	阿里云
	case "aliyun":
		accessKeyId := string(smsSecret.Data["accessKeyId"])
		accessKeySecret := string(smsSecret.Data["accessKeySecret"])
		notice := string(smsSecret.Data["notice"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = aliyun.GateWay(accessKeyId, accessKeySecret)
		//var message = gosms.MessageContent("您的验证码是：****。请不要把验证码泄露给其他人。")
		var message = gosms.MessageContent(fmt.Sprintf(notice, otpstr))
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(aliyun.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, err)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	聚合数据
	case "juhe":
		key := string(smsSecret.Data["key"])
		templateId := string(smsSecret.Data["templateId"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = juhe.GateWay(key)
		var message = gosms.MessageTemplate(templateId, gosms.MapStrings{
			"code": otpstr,
		})
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(juhe.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, err)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	微网通联
	case "lmobile":
		account := string(smsSecret.Data["account"])
		password := string(smsSecret.Data["password"])
		productId := string(smsSecret.Data["productId"])
		notice := string(smsSecret.Data["notice"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = lmobile.GateWay(account, password, productId)
		//var message = gosms.MessageContent("您的验证码是：****。请不要把验证码泄露给其他人。")
		var message = gosms.MessageContent(fmt.Sprintf(notice, otpstr))
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(lmobile.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, err)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	短信宝
	case "smsbao":
		account := string(smsSecret.Data["account"])
		password := string(smsSecret.Data["password"])
		notice := string(smsSecret.Data["notice"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = smsbao.GateWay(account, password)
		//var message = gosms.MessageContent("您的验证码是：****。请不要把验证码泄露给其他人。")
		var message = gosms.MessageContent(fmt.Sprintf(notice, otpstr))
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(smsbao.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, err)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	//	网易云信
	case "yunxin":
		account := string(smsSecret.Data["account"])
		password := string(smsSecret.Data["password"])
		templateId := string(smsSecret.Data["templateId"])
		var number = gosms.NoCodePhoneNumber(phone)
		var gateway = yunxin.GateWay(account, password)
		//var message = gosms.MessageContent("您的验证码是：****。请不要把验证码泄露给其他人。")
		var message = gosms.MessageTemplate(templateId, gosms.MapStrings{
			"code":   otpstr,
			"action": "sendCode",
		})
		result, err := gosms.Sender(number, message, gateway)
		resp, ok := result.ClientResult.Response.(yunxin.Response)
		if !ok {
			log.Fatal(err)
			response.WriteHeaderAndEntity(http.StatusBadRequest, err)
			return
		}
		response.WriteHeaderAndEntity(http.StatusOK, resp)
	default:
		response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Sprintf("serviceProvider:%v not supported", smsServiceProvider))
		return
	}

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

			if errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil && !user.Spec.FAOpenStatus {
			p.setOtpOpen(req, response, user, issuer)
		}

	}
	ok := map[string]string{
		"Msg": "ok",
	}
	response.WriteHeaderAndEntity(http.StatusOK, ok)
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
			Orig: b32NoPadding.EncodeToString([]byte(key.String())),
			Url: &iamv1alpha2.OtpURL{
				Scheme: u.Scheme,
				Opaque: u.Opaque,
				User: &iamv1alpha2.OtpUrlUserinfo{
					Username:    b32NoPadding.EncodeToString([]byte(otpUsername)),
					Password:    b32NoPadding.EncodeToString([]byte(otpPassword)),
					PasswordSet: otpPasswordSet,
				},
				Host:        b32NoPadding.EncodeToString([]byte(u.Host)),
				Path:        b32NoPadding.EncodeToString([]byte(u.Path)),
				RawPath:     b32NoPadding.EncodeToString([]byte(u.RawPath)),
				OmitHost:    u.OmitHost,
				ForceQuery:  u.ForceQuery,
				RawQuery:    b32NoPadding.EncodeToString([]byte(u.RawQuery)),
				Fragment:    b32NoPadding.EncodeToString([]byte(u.Fragment)),
				RawFragment: b32NoPadding.EncodeToString([]byte(u.RawFragment)),
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
			if errors.IsNotFound(err) {
				klog.Error(err)
				response.WriteHeaderAndEntity(http.StatusBadRequest, oauth.NewInvalidRequest(err))
				return
			}
		}
		if user != nil && !user.Spec.FAOpenStatus {
			p.setSmsOpen(request, response, user)
		}

	}
	ok := map[string]string{
		"Msg": "ok",
	}
	response.WriteHeaderAndEntity(http.StatusOK, ok)
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
				Orig: b32NoPadding.EncodeToString([]byte(key.String())),
				Url: &iamv1alpha2.OtpURL{
					Scheme: u.Scheme,
					Opaque: u.Opaque,
					User: &iamv1alpha2.OtpUrlUserinfo{
						Username:    b32NoPadding.EncodeToString([]byte(otpUsername)),
						Password:    b32NoPadding.EncodeToString([]byte(otpPassword)),
						PasswordSet: otpPasswordSet,
					},
					Host:        b32NoPadding.EncodeToString([]byte(u.Host)),
					Path:        b32NoPadding.EncodeToString([]byte(u.Path)),
					RawPath:     b32NoPadding.EncodeToString([]byte(u.RawPath)),
					OmitHost:    u.OmitHost,
					ForceQuery:  u.ForceQuery,
					RawQuery:    b32NoPadding.EncodeToString([]byte(u.RawQuery)),
					Fragment:    b32NoPadding.EncodeToString([]byte(u.Fragment)),
					RawFragment: b32NoPadding.EncodeToString([]byte(u.RawFragment)),
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
func (p *passcodeAuthenticator) Get2faConfig(request *restful.Request, response *restful.Response) {
	cm, err := p.k8sClient.CoreV1().ConfigMaps(constants.KubeSphereNamespace).Get(context.TODO(), constants.KubeSphereMultauthConfigName, metav1.GetOptions{})
	if err != nil {
		klog.Error(err)
	}
	configData := &config.Config{}
	value, ok := cm.Data[constants.KubeSphereMultauthConfigMapDataKey]
	if !ok {
		klog.Error(fmt.Errorf("failed to get configmap multauth-config.yaml value"))
		response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to get configmap multauth-config.yaml value"))
		return
	}
	if err := yaml.Unmarshal([]byte(value), configData); err != nil {
		klog.Error(fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
		response.WriteHeaderAndEntity(http.StatusBadRequest, fmt.Errorf("failed to unmarshal value from configmap. err: %s", err))
		return
	}

	if err != nil {
		klog.Error(err)
	}
	if configData.MultiauthOptions == nil {
		configData.MultiauthOptions = &multiauth.Options{}
	}

	res := map[string]string{
		"faOpenStatus": fmt.Sprintf("%t", configData.MultiauthOptions.FAOpenStatus),
		"faType":       configData.MultiauthOptions.FAType,
		"issuer":       configData.MultiauthOptions.Issuer,
	}
	response.WriteHeaderAndEntity(http.StatusOK, res)
}
