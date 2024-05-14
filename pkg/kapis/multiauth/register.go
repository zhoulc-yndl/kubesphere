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
	"kubesphere.io/kubesphere/pkg/api"
	resourcev1alpha3 "kubesphere.io/kubesphere/pkg/models/resources/v1alpha3/resource"
	"net/http"

	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"

	"kubesphere.io/kubesphere/pkg/constants"
	"kubesphere.io/kubesphere/pkg/models/auth"
	"kubesphere.io/kubesphere/pkg/models/iam/im"
)

const contentTypeFormData = "application/x-www-form-urlencoded"

// AddToContainer ks-apiserver includes a built-in OAuth server. Users obtain OAuth access tokens to authenticate themselves to the API.
// The OAuth server supports standard authorization code grant and the implicit grant OAuth authorization flows.
// All requests for OAuth tokens involve a request to <ks-apiserver>/oauth/authorize.
// Most authentication integrations place an authenticating proxy in front of this endpoint, or configure ks-apiserver
// to validate credentials against a backing identity provider.
// Requests to <ks-apiserver>/oauth/authorize can come from user-agents that cannot display interactive login pages, such as the CLI.
func AddToContainer(c *restful.Container, im im.IdentityManagementInterface,
	passcodeAuthenticator auth.PasscodeAuthenticator,
	resourceGetterV1alpha3 *resourcev1alpha3.ResourceGetter,
) error {

	ws := &restful.WebService{}
	ws.Path("/kapis/multauth").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)

	handler := newHandler(im, passcodeAuthenticator, resourceGetterV1alpha3)

	// enable otp
	ws.Route(ws.POST("/enable_2fa").
		Consumes(contentTypeFormData).
		Param(ws.FormParameter("username", "The otp username.").Required(false)).
		Param(ws.FormParameter("issuer", "The otp issuer.").Required(false)).
		Param(ws.FormParameter("global", "The otp global flag.").Required(true)).
		Param(ws.FormParameter("faType", "The 2fa type.").Required(true)).
		To(handler.enable2fa).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	// reset otp
	ws.Route(ws.POST("/reset_otp").
		Consumes(contentTypeFormData).
		Param(ws.FormParameter("username", "The otp username.").Required(true)).
		Param(ws.FormParameter("issuer", "The otp issuer.").Required(true)).
		To(handler.resetOtp).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	// disable otp
	ws.Route(ws.POST("/disable_2fa").
		Consumes(contentTypeFormData).
		Param(ws.FormParameter("username", "The otp username.").Required(false)).
		Param(ws.FormParameter("global", "The otp global flag.").Required(true)).
		To(handler.disable2fa).
		Returns(http.StatusOK, http.StatusText(http.StatusOK), "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	// get 2fa config
	ws.Route(ws.GET("/get_2fa_config").
		To(handler.get2faConfig).
		Doc("get 2fa config").
		Reads(LoginRequest{}).
		Returns(http.StatusOK, api.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	// get otp png
	ws.Route(ws.GET("/otp/barcode").
		To(handler.otpBarcode).
		Deprecate().
		Doc("get otp barcode").
		Reads(LoginRequest{}).
		Returns(http.StatusOK, api.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	ws.Route(ws.POST("/sms/send").
		To(handler.sendMessage).
		Deprecate().
		Doc("send sms passcode").
		Reads(LoginRequest{}).
		Returns(http.StatusOK, api.StatusOK, "").
		Metadata(restfulspec.KeyOpenAPITags, []string{constants.AuthenticationTag}))

	c.Add(ws)

	return nil
}
