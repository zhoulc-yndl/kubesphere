/*
Copyright 2020 The KubeSphere Authors.

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

package multauth

import (
	"k8s.io/client-go/kubernetes"
	resourcev1alpha3 "kubesphere.io/kubesphere/pkg/models/resources/v1alpha3/resource"
	"net/http"

	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"

	"github.com/emicklei/go-restful"
	"k8s.io/apiserver/pkg/authentication/user"
	"kubesphere.io/kubesphere/pkg/api"
	"kubesphere.io/kubesphere/pkg/apiserver/request"
	"kubesphere.io/kubesphere/pkg/models/auth"
	"kubesphere.io/kubesphere/pkg/models/iam/im"
)

type Status struct {
	Authenticated bool                   `json:"authenticated" description:"is authenticated"`
	User          map[string]interface{} `json:"user,omitempty" description:"user info"`
}

type LoginRequest struct {
	Username string `json:"username" description:"username"`
	Password string `json:"password" description:"password"`
	Passcode string `json:"passcode,omitempty" description:"passcode"`
}

type handler struct {
	im                     im.IdentityManagementInterface
	passcodeAuthenticator  auth.PasscodeAuthenticator
	resourceGetterV1alpha3 *resourcev1alpha3.ResourceGetter
	k8sClient              kubernetes.Interface
}

func newHandler(im im.IdentityManagementInterface,
	passcodeAuthenticator auth.PasscodeAuthenticator,
	resourceGetterV1alpha3 *resourcev1alpha3.ResourceGetter,
) *handler {
	return &handler{im: im,
		passcodeAuthenticator:  passcodeAuthenticator,
		resourceGetterV1alpha3: resourceGetterV1alpha3}
}

func (h *handler) enable2fa(req *restful.Request, response *restful.Response) {

	// 根据token获取用户信息
	authenticated, _ := request.UserFrom(req.Request.Context())
	if authenticated == nil || authenticated.GetName() == user.Anonymous {
		response.WriteHeaderAndEntity(http.StatusUnauthorized, oauth.ErrorLoginRequired)
		return
	}
	detail, err := h.im.DescribeUser(authenticated.GetName())
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusInternalServerError, oauth.NewServerError(err))
		return
	}
	//判断用户角色，普通用户无权限设置双因素认证
	isAdmin := h.passcodeAuthenticator.IsAdmin(detail.Name)
	if isAdmin {
		username := req.QueryParameter("username")
		issuer := req.QueryParameter("issuer")
		global := req.QueryParameter("global")
		faType := req.QueryParameter("faType")
		if faType == "" {
			response.WriteHeaderAndEntity(http.StatusBadRequest, "faType is null")
			return
		}

		//else if faType == iamv1alpha2.FATypeOtp {
		//	if issuer == "" {
		//		response.WriteHeaderAndEntity(http.StatusBadRequest, "issuer is null")
		//		return
		//	}
		//	h.passcodeAuthenticator.EnableOTP(req, response, username, issuer, global)
		//} else if faType == iamv1alpha2.FATypeSms {
		//	if username == "" {
		//		response.WriteHeaderAndEntity(http.StatusBadRequest, "username is null")
		//		return
		//	}
		//	h.passcodeAuthenticator.EnableSMS(req, response, username, global)
		//}
		h.passcodeAuthenticator.Enable2fa(req, response, username, issuer, faType, global)
	} else {
		response.WriteHeaderAndEntity(http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

}

func (h *handler) disable2fa(req *restful.Request, response *restful.Response) {
	// 根据token获取用户信息
	authenticated, _ := request.UserFrom(req.Request.Context())
	if authenticated == nil || authenticated.GetName() == user.Anonymous {
		response.WriteHeaderAndEntity(http.StatusUnauthorized, oauth.ErrorLoginRequired)
		return
	}
	detail, err := h.im.DescribeUser(authenticated.GetName())
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusInternalServerError, oauth.NewServerError(err))
		return
	}
	//判断用户角色，普通用户无权限设置双因素认证
	isAdmin := h.passcodeAuthenticator.IsAdmin(detail.Name)
	if isAdmin {
		username := req.QueryParameter("username")
		global := req.QueryParameter("global")
		h.passcodeAuthenticator.Disable2fa(req, response, username, global)
	} else {
		response.WriteHeaderAndEntity(http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

}

func (h *handler) otpBarcode(req *restful.Request, response *restful.Response) {
	//// 根据token获取用户信息
	//authenticated, _ := request.UserFrom(req.Request.Context())
	//if authenticated == nil || authenticated.GetName() == user.Anonymous {
	//	response.WriteHeaderAndEntity(http.StatusUnauthorized, oauth.ErrorLoginRequired)
	//	return
	//}
	//detail, err := h.im.DescribeUser(authenticated.GetName())
	//if err != nil {
	//	response.WriteHeaderAndEntity(http.StatusInternalServerError, oauth.NewServerError(err))
	//	return
	//}

	username := req.QueryParameter("username")
	//判断用户角色，普通用户只能获取自己的otp二维码
	isAdmin := h.passcodeAuthenticator.IsAdmin(username)
	if isAdmin {

		if username == "" {
			response.WriteErrorString(http.StatusBadRequest, "username is null")
			return
		}
		h.passcodeAuthenticator.OtpBarcode(req, response, username)
	} else {
		h.passcodeAuthenticator.OtpBarcode(req, response, username)
	}

}

func (h *handler) resetOtp(req *restful.Request, response *restful.Response) {
	// 根据token获取用户信息
	authenticated, _ := request.UserFrom(req.Request.Context())
	if authenticated == nil || authenticated.GetName() == user.Anonymous {
		response.WriteHeaderAndEntity(http.StatusUnauthorized, oauth.ErrorLoginRequired)
		return
	}
	detail, err := h.im.DescribeUser(authenticated.GetName())
	if err != nil {
		response.WriteHeaderAndEntity(http.StatusInternalServerError, oauth.NewServerError(err))
		return
	}

	//判断用户角色，普通用户只能获取自己的otp二维码
	isAdmin := h.passcodeAuthenticator.IsAdmin(detail.Name)
	if isAdmin {
		username := req.QueryParameter("username")
		issuer := req.QueryParameter("issuer")
		if username == "" {
			response.WriteErrorString(http.StatusBadRequest, "username is null")
			return
		}
		h.passcodeAuthenticator.ResetOTP(req, response, username, issuer)
	}

}
func (h *handler) sendMessage(req *restful.Request, response *restful.Response) {
	var loginRequest LoginRequest
	err := req.ReadEntity(&loginRequest)
	if err != nil {
		api.HandleBadRequest(response, req, err)
		return
	}
	secret, err := h.resourceGetterV1alpha3.Get("secrets", "default", "global-sms-config-secret")
	if err != nil {
		api.HandleBadRequest(response, req, err)
		return
	}
	h.passcodeAuthenticator.SendMessage(req, response, loginRequest.Username, secret)
}
func (h *handler) get2faConfig(req *restful.Request, response *restful.Response) {
	h.passcodeAuthenticator.Get2faConfig(req, response)
}
