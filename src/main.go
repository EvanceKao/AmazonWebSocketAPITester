package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	//"github.com/aws/aws-sdk-go/aws"
	//"github.com/aws/aws-sdk-go/aws/credentials"
	//"github.com/aws/aws-sdk-go/aws/request"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bmizerany/aws4"
	"github.com/kataras/iris"
)

const iSO8601BasicFormat = "20060102T150405Z"
const iSO8601BasicFormatShort = "20060102"

var lf = []byte{'\n'}
var algorithm string = "AWS4-HMAC-SHA256"

// User is just a bindable object structure.
type User struct {
	Username  string `json:"username"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	City      string `json:"city"`
	Age       int    `json:"age"`
}

type AWSApiGatewayRequest struct {
	ConnectionUrl string `json:"connectionUrl"`
	Message       string `json:"message"`
	AccessKey     string `json:"accessKey"`
	SecretKey     string `json:"secretKey"`
	RegionName    string `json:"regionName"`
	ServiceName   string `json:"serviceName"`
}

type AWSClient struct {
	//Client *aws4.Client
	Keys *aws4.Keys

	// The http client to make requests with. If nil, http.DefaultClient is used.
	Client *http.Client
}

// Service represents an AWS-compatible service.
type AWSService struct {
	// Name is the name of the service being used (i.e. iam, etc)
	Name string

	// Region is the region you want to communicate with the service through. (i.e. us-east-1)
	Region string
}

type Response struct {
	StatusCode string
	Body       string
}

func main() {
	app := iris.New()
	// app.Logger().SetLevel("disable") to disable the logger

	// Define templates using the std html/template engine.
	// Parse and load all files inside "./views" folder with ".html" file extension.
	// Reload the templates on each request (development mode).
	app.RegisterView(iris.HTML("./views", ".html").Reload(true))

	// register static assets request path and system directory
	app.HandleDir("/js", "./js")
	app.HandleDir("/css", "./css")

	// Register custom handler for specific http errors.
	app.OnErrorCode(iris.StatusInternalServerError, func(ctx iris.Context) {
		// .Values are used to communicate between handlers, middleware.
		errMessage := ctx.Values().GetString("error")
		if errMessage != "" {
			ctx.Writef("Internal server error: %s", errMessage)
			return
		}

		ctx.Writef("(Unexpected) internal server error")
	})

	// context.Handler 类型 每一个请求都会先执行此方法 app.Use(context.Handler)
	app.Use(func(ctx iris.Context) {
		ctx.Application().Logger().Infof("Begin request for path: %s", ctx.Path())
		ctx.Next()
	})

	// context.Handler 类型 每一个请求最后执行 app.Done(context.Handler)
	app.Done(func(ctx iris.Context) {})

	// POST: scheme://mysubdomain.$domain.com/decode
	app.Subdomain("mysubdomain.").Post("/decode", func(ctx iris.Context) {})

	// Method POST: http://localhost:8080/decode
	app.Post("/decode", func(ctx iris.Context) {
		var user User
		ctx.ReadJSON(&user)
		ctx.Writef("%s %s is %d years old and comes from %s", user.Firstname, user.Lastname, user.Age, user.City)
	})

	// Method GET: http://localhost:8080/encode
	app.Get("/encode", func(ctx iris.Context) {
		doe := User{
			Username:  "Johndoe",
			Firstname: "John",
			Lastname:  "Doe",
			City:      "Neither FBI knows!!!",
			Age:       25,
		}

		ctx.JSON(doe)
	})

	// Method GET: http://localhost:8080/profile/anytypeofstring
	// 当不明确定义传值类型的时候，默认为字符串类型
	// app.Get("/profile/{username}", profileByUsername) 等同于下面的
	app.Get("/profile/{username:string}", profileByUsername)

	//app.Party 定义路由组  第一个参数 设置路由相同的前缀 第二个参数为中间件
	usersRoutes := app.Party("/users", logThisMiddleware)
	{
		// Method GET: http://localhost:8080/users/42
		// 表示 id 必须是 int 类型 最小值为 1
		usersRoutes.Get("/{id:int min(1)}", getUserByID)
		// Method POST: http://localhost:8080/users/create
		usersRoutes.Post("/create", createUser)
	}

	// Method GET: http://localhost:8080/test
	app.Get("/test", func(ctx iris.Context) {
		//ctx.ViewData("TestMessage", "- this is send from golang")
		ctx.View("test.html")
	})

	// Method GET: http://localhost:8080/test
	app.Get("/test/{apiName:string}", func(ctx iris.Context) {
		apiName := ctx.Params().Get("apiName")
		ctx.ViewData("TestMessage", "- "+apiName)
		ctx.View("test.html")
	})

	//app.PartyFunc("/aws", func(aws iris.Party) {
	//	aws.Use(myAuthMiddlewareHandler)
	//})

	awsBackendRoutes := app.Party("/awsbackend", logThisMiddleware)
	{
		//// Method GET: http://localhost:8080/awsbackend/apiId.execute-api.us-west-2.amazonaws.com/dev/42
		//awsBackendRoutes.Get("/{url:string}/{stage:string}/{connectionId:string}", func(ctx iris.Context) {
		//	apiName := ctx.Params().Get("apiName")
		//	ctx.ViewData("TestMessage", "- "+apiName)
		//	ctx.View("test.html")
		//})

		// Method POST: http://localhost:8080/awsbackend/GetStatus/B8n2gcXlPHcCJTA%3D
		awsBackendRoutes.Post("/GetStatus/{connectionId:string}", func(ctx iris.Context) {
			connectionId := ctx.Params().Get("connectionId")

			var awsApiGatewayRequest AWSApiGatewayRequest
			ctx.ReadJSON(&awsApiGatewayRequest)
			//ctx.Writef("request: %s", awsApiGatewayRequest)
			ctx.Application().Logger().Infof("request: %s | connection Id: %s | IP: %s", awsApiGatewayRequest, connectionId, ctx.RemoteAddr())

			//keys := aws4.Keys{
			//	AccessKey: "AccessKey",
			//	SecretKey: "SecretKey/SecretKey",
			//}

			awsApiGatewayRequest.AccessKey = "AccessKey"
			awsApiGatewayRequest.SecretKey = "SecretKey/SecretKey"

			originUrl := awsApiGatewayRequest.ConnectionUrl + strings.ReplaceAll(connectionId, "=", "%3D")
			ctx.Application().Logger().Infof("Origin url: %s", originUrl)
			//baseUrl, err := url.Parse(originUrl)
			//if err != nil {
			//	ctx.Application().Logger().Infof("Malformed URL: ", err.Error())
			//	return
			//}
			encodeUrl := url.QueryEscape(originUrl)
			ctx.Application().Logger().Infof("Url encode: %s", encodeUrl)

			//encodeUrl = "https://apiId.execute-api.us-west-2.amazonaws.com/dev/%40connections/B8n2gcXlPHcCJTA%3D"
			//
			//timeNow := time.Now().UTC()
			//dateStamp := timeNow.Format(iSO8601BasicFormatShort)
			//regionName := awsApiGatewayRequest.RegionName
			//serviceName := awsApiGatewayRequest.ServiceName
			//// []byte
			//signatureKey := createSignatureKey(keys.SecretKey, dateStamp, regionName, serviceName)

			//req, err := http.NewRequest("GET", awsApiGatewayRequest.Url, nil)
			//originUrl = "https://apiId.execute-api.us-west-2.amazonaws.com/dev/@connections/B8n2gcXlPHcCJTA="
			req, _ := http.NewRequest(http.MethodGet, originUrl, nil)
			req.Header.Set("content-type", "application/x-www-form-urlencoded")
			//req.Proto = "HTTP/1.2"

			Sign(req, time.Now().UTC(), awsApiGatewayRequest, ctx)
			ctx.Application().Logger().Infof("Authorization: %s", req.Header["Authorization"])

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}

			defer resp.Body.Close()
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}
			bodyString := string(bodyBytes)

			var response Response
			response.StatusCode = resp.Status
			response.Body = bodyString

			ctx.JSON(response)
			//ctx.Writef("{\"stautsCode\": resp.Status, \"body\": " + bodyString + "}")

			////lkjkl
			//
			//awsClient := aws4.Client{Keys: &keys}
			//
			//resp, err := awsClient.Do(req)
			//ctx.Application().Logger().Infof("Authorization: %s", req.Header["Authorization"])
			//
			//if err != nil {
			//	ctx.Application().Logger().Fatal(err)
			//}
			//
			//defer resp.Body.Close()
			//bodyBytes, err := ioutil.ReadAll(resp.Body)
			//bodyString := string(bodyBytes)
			//
			//ctx.Writef(resp.Status + "\r\n" + bodyString)

			//ctx.JSON(doe)
			//apiName := ctx.Params().Get("apiName")
			//ctx.ViewData("TestMessage", "- "+apiName)
			//ctx.View("test.html")
		})

		// Method POST: http://localhost:8080/awsbackend/SendMessage/B8n2gcXlPHcCJTA%3D
		awsBackendRoutes.Post("/SendMessage/{connectionId:string}", func(ctx iris.Context) {
			connectionId := ctx.Params().Get("connectionId")

			var awsApiGatewayRequest AWSApiGatewayRequest
			ctx.ReadJSON(&awsApiGatewayRequest)
			//ctx.Writef("request: %s", awsApiGatewayRequest)
			ctx.Application().Logger().Infof("request: %s | connection Id: %s | IP: %s", awsApiGatewayRequest, connectionId, ctx.RemoteAddr())

			awsApiGatewayRequest.AccessKey = "AccessKey"
			awsApiGatewayRequest.SecretKey = "SecretKey/SecretKey"

			originUrl := awsApiGatewayRequest.ConnectionUrl + strings.ReplaceAll(connectionId, "=", "%3D")
			ctx.Application().Logger().Infof("Origin url: %s", originUrl)

			var jsonStr = []byte("{\"message\":\"" + awsApiGatewayRequest.Message + "\"}")
			ctx.Application().Logger().Infof("POST json: %s", jsonStr)

			req, _ := http.NewRequest(http.MethodPost, originUrl, bytes.NewBuffer(jsonStr))
			req.Header.Set("content-type", "application/json")
			//req.Proto = "HTTP/1.2"

			Sign(req, time.Now().UTC(), awsApiGatewayRequest, ctx)
			ctx.Application().Logger().Infof("Authorization: %s", req.Header["Authorization"])

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}

			defer resp.Body.Close()
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}
			bodyString := string(bodyBytes)

			var response Response
			response.StatusCode = resp.Status
			response.Body = bodyString

			ctx.JSON(response)
		})

		// Method POST: http://localhost:8080/awsbackend/DeleteConnection/B8n2gcXlPHcCJTA%3D
		awsBackendRoutes.Post("/DeleteConnection/{connectionId:string}", func(ctx iris.Context) {
			connectionId := ctx.Params().Get("connectionId")

			var awsApiGatewayRequest AWSApiGatewayRequest
			ctx.ReadJSON(&awsApiGatewayRequest)
			//ctx.Writef("request: %s", awsApiGatewayRequest)
			ctx.Application().Logger().Infof("request: %s | connection Id: %s | IP: %s", awsApiGatewayRequest, connectionId, ctx.RemoteAddr())

			awsApiGatewayRequest.AccessKey = "AccessKey"
			awsApiGatewayRequest.SecretKey = "SecretKey/SecretKey"

			originUrl := awsApiGatewayRequest.ConnectionUrl + strings.ReplaceAll(connectionId, "=", "%3D")
			ctx.Application().Logger().Infof("Origin url: %s", originUrl)

			req, _ := http.NewRequest(http.MethodDelete, originUrl, nil)
			req.Header.Set("content-type", "application/json")
			//req.Proto = "HTTP/1.2"

			Sign(req, time.Now().UTC(), awsApiGatewayRequest, ctx)
			ctx.Application().Logger().Infof("Authorization: %s", req.Header["Authorization"])

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}

			defer resp.Body.Close()
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ctx.Application().Logger().Fatal(err)
				//return
			}
			bodyString := string(bodyBytes)

			var response Response
			response.StatusCode = resp.Status
			response.Body = bodyString

			ctx.JSON(response)
		})
	}

	// Listen for incoming HTTP/1.x & HTTP/2 clients on localhost port 8080.
	app.Run(iris.Addr(":8080"), iris.WithCharset("UTF-8"))
}

func logThisMiddleware(ctx iris.Context) {
	// ctx.Path() 请求的url
	ctx.Application().Logger().Infof("Path: %s | IP: %s", ctx.Path(), ctx.RemoteAddr())

	// .Next is required to move forward to the chain of handlers,
	// if missing then it stops the execution at this handler.
	ctx.Next()
}

func profileByUsername(ctx iris.Context) {
	// .Params are used to get dynamic path parameters.
	// 获取路由参数
	username := ctx.Params().Get("username")

	// 向数据模板传值 当然也可以绑定其他值
	ctx.ViewData("Username", username)

	// renders "./views/user/profile.html"
	// with {{ .Username }} equals to the username dynamic path parameter.
	ctx.View("user/profile.html")
}

func getUserByID(ctx iris.Context) {
	// 下面的可以转换成  .Values().GetInt/GetInt64
	// ctx.Values().GetInt("id")
	userID := ctx.Params().Get("id") // Or convert directly using: .Values().GetInt/GetInt64 etc...
	// your own db fetch here instead of user :=...
	user := User{Username: "username" + userID}

	// xml 输出
	ctx.XML(user)
}

func createUser(ctx iris.Context) {
	var user User
	// ctx.ReadForm 格式请求数据 与 ctx.ReadJSON 相似 不过接收的是 Form 请求
	// 记住 post 字段取名  Username 结构体字段体
	err := ctx.ReadForm(&user)
	if err != nil {
		ctx.Values().Set("error", "creating user, read and parse form failed. "+err.Error())
		ctx.StatusCode(iris.StatusInternalServerError)
		return
	}

	// renders "./views/user/create_verification.html"
	// with {{ . }} equals to the User object, i.e {{ .Username }} , {{ .Firstname}} etc...
	ctx.ViewData("", user)
	ctx.View("user/create_verification.html")
}

//func (c *AWSClient) DoApi(req *http.Request) (resp *http.Response, err error) {
//	Sign(c.Keys, req)
//	return c.client().Do(req)
//}
//
//func Sign(keys *aws4.Keys, r *http.Request) error {
//	parts := strings.Split(r.Host, ".")
//	if len(parts) < 4 {
//		return fmt.Errorf("Invalid AWS Endpoint: %s", r.Host)
//	}
//	sv := new(aws4.Service)
//	sv.Name = strings.ReplaceAll(strings.ReplaceAll(parts[0], "http://", ""), "https://", "")
//	sv.Region = parts[2]
//	sv.Sign(keys, r)
//	return nil
//}
//
//func (c *AWSClient) client() *http.Client {
//	if c.Client == nil {
//		return http.DefaultClient
//	}
//	return c.Client
//}

//// Sign signs an HTTP request with the given AWS keys for use on service s.
//func (s *AWSService) Sign(keys *aws4.Keys, r *http.Request) error {
//	date := r.Header.Get("Date")
//	t := time.Now().UTC()
//	if date != "" {
//		var err error
//		t, err = time.Parse(http.TimeFormat, date)
//		if err != nil {
//			return err
//		}
//	}
//	r.Header.Set("Date", t.Format(iSO8601BasicFormat))
//
//	k := keys.sign(s, t)
//	h := hmac.New(sha256.New, k)
//	s.writeStringToSign(h, t, r)
//
//	auth := bytes.NewBufferString("AWS4-HMAC-SHA256 ")
//	auth.Write([]byte("Credential=" + keys.AccessKey + "/" + s.creds(t)))
//	auth.Write([]byte{',', ' '})
//	auth.Write([]byte("SignedHeaders="))
//	s.writeHeaderList(auth, r)
//	auth.Write([]byte{',', ' '})
//	auth.Write([]byte("Signature=" + fmt.Sprintf("%x", h.Sum(nil))))
//
//	r.Header.Set("Authorization", auth.String())
//
//	return nil
//}

func getURIPath(u *url.URL) string {
	var uri string

	if len(u.Opaque) > 0 {
		uri = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		uri = u.EscapedPath()
	}

	if len(uri) == 0 {
		uri = "/"
	}

	return uri
}

func ghmac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func toHexString(b []byte) string {
	return fmt.Sprintf("%x", b)
}

func urlencode(s string) (result string) {
	for _, c := range s {
		if c <= 0x7f { // single byte
			result += fmt.Sprintf("%%%X", c)
		} else if c > 0x1fffff { // quaternary byte
			result += fmt.Sprintf("%%%X%%%X%%%X%%%X",
				0xf0+((c&0x1c0000)>>18),
				0x80+((c&0x3f000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else if c > 0x7ff { // triple byte
			result += fmt.Sprintf("%%%X%%%X%%%X",
				0xe0+((c&0xf000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else { // double byte
			result += fmt.Sprintf("%%%X%%%X",
				0xc0+((c&0x7c0)>>6),
				0x80+(c&0x3f),
			)
		}
	}

	return result
}

func createSignatureKey(secretKey string, dateStamp string, regionName string, serviceName string) []byte {
	kDate := ghmac([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := ghmac(kDate, []byte(regionName))
	kService := ghmac(kRegion, []byte(serviceName))
	kSigning := ghmac(kService, []byte("aws4_request"))
	return kSigning
}

//func createCanonicalRequest(httpMethod string, canonicalURI string, canonicalQueryString string, canonicalHeaders string, signedHeaders string, requestPayload string) string {
//	var createCanonicalRequest string = ""
//	createCanonicalRequest += httpMethod + "\n"
//	createCanonicalRequest += canonicalURI + "\n"
//	createCanonicalRequest += canonicalQueryString + "\n"
//	createCanonicalRequest += canonicalHeaders + "\n"
//	createCanonicalRequest += signedHeaders + "\n"
//	createCanonicalRequest += requestPayload
//	return createCanonicalRequest
//}

func createCanonicalRequest(httpRequest *http.Request, payLoadHash string, ctx iris.Context) (string, string) {
	var canonicalRequest string = ""
	canonicalRequest += httpRequest.Method + "\n"
	canonicalRequest += createCanonicalUri(httpRequest) + "\n"
	canonicalRequest += createCanonicalQueryString(httpRequest) + "\n"
	canonicalHeaders, signedHeaders := createCanonicalHeaders(httpRequest)
	canonicalRequest += canonicalHeaders + "\n\n"
	canonicalRequest += signedHeaders + "\n"
	//createCanonicalRequest += createCanonicalPayLoadHash(httpRequest)
	canonicalRequest += payLoadHash
	return canonicalRequest, signedHeaders
}

func createCanonicalUri(r *http.Request) string {
	//uri := getURIPath(r.URL)

	//if !v4.DisableURIPathEscaping {
	//	uri = rest.EscapePath(uri, false)
	//}

	//return uri

	path := r.URL.RequestURI()
	//if r.URL.RawQuery != "" {
	//	path = path[:len(path)-len(r.URL.RawQuery)-1]
	//}
	//slash := strings.HasSuffix(path, "/")
	//path = filepath.Clean(path)
	//if path != "/" && slash {
	//	path += "/"
	//}

	a := strings.Split(path, "/")
	if len(a) == 0 {
		return "/"
	}

	for index := 0; index < len(a); index++ {
		//urlencode
		//a[index] = urlencode(a[index])
		//a[index] = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(a[index], "@", "%40"), "=", "%3D"), "%", "%25")
		//a[index] = url.QueryEscape(url.QueryEscape(a[index]))
		a[index] = url.QueryEscape(a[index])
	}

	//return "/dev/%!c(MISSING)onnections/B8n2gcXlPHcCJTA%!D(MISSING)"

	//return path
	return strings.Join(a, "/")
}

func createCanonicalQueryString(r *http.Request) string {
	r.URL.RawQuery = strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	return r.URL.RawQuery

	var a []string
	for k, vs := range r.URL.Query() {
		k = url.QueryEscape(k)
		for _, v := range vs {
			if v == "" {
				a = append(a, k)
			} else {
				v = url.QueryEscape(v)
				a = append(a, k+"="+v)
			}
		}
	}
	sort.Strings(a)
	return strings.Join(a, "&")
}

func createCanonicalHeaders(r *http.Request) (string, string) {
	i, a := 0, make([]string, len(r.Header))
	var signedHeadersList []string
	for k, v := range r.Header {
		sort.Strings(v)
		a[i] = strings.ToLower(k) + ":" + strings.Join(v, ",")
		signedHeadersList = append(signedHeadersList, strings.ToLower(k))
		i++
	}
	sort.Strings(a)
	return strings.Join(a, "\n"), strings.Join(signedHeadersList, ";")
}

func createCanonicalPayLoadHash(r *http.Request) string {
	var b []byte
	b = []byte("")

	// If the payload is empty, use the empty string as the input to the SHA256 function
	// http://docs.amazonwebservices.com/general/latest/gr/sigv4-create-canonical-request.html
	if r.Body == nil {
		b = []byte("")
	} else {
		var err error
		b, err = ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	}

	h := sha256.New()
	h.Write(b)
	//payLoadHash := string(h.Sum(nil))
	payLoadHash := toHexString(h.Sum(nil))
	payLoadHash = strings.ToLower(payLoadHash)
	return payLoadHash
}

func createCredentialScope(dateStamp string, regionName string, serviceName string) string {
	return dateStamp + "/" + regionName + "/" + serviceName + "/" + "aws4_request"
}

func createStringToSign(amzDate string, credentialScope string, canonicalRequest string) []byte {
	var a []string
	a = append(a, algorithm)
	a = append(a, amzDate)
	a = append(a, credentialScope)

	h := sha256.New()
	h.Write([]byte(canonicalRequest))
	//canonicalRequestHash := string(h.Sum(nil))
	canonicalRequestHash := toHexString(h.Sum(nil))
	a = append(a, canonicalRequestHash)

	return []byte(strings.Join(a, "\n"))
}

func Sign(r *http.Request, timeNow time.Time, awsApiGatewayRequest AWSApiGatewayRequest, ctx iris.Context) {
	r.Header.Set("host", r.Host)

	payLoadHash := createCanonicalPayLoadHash(r)
	//r.Header.Set("x-amz-content-sha256", payLoadHash)
	//r.Header.Set("x-amz-content-sha256", payLoadHash)

	amzDate := timeNow.Format(iSO8601BasicFormat)
	r.Header.Set("x-amz-date", amzDate)

	dateStamp := timeNow.Format(iSO8601BasicFormatShort)
	regionName := awsApiGatewayRequest.RegionName
	serviceName := awsApiGatewayRequest.ServiceName
	accessKey := awsApiGatewayRequest.AccessKey
	secretKey := awsApiGatewayRequest.SecretKey

	credentialScope := createCredentialScope(dateStamp, regionName, serviceName)
	ctx.Application().Logger().Infof("credentialScope: %s", credentialScope)

	canonicalRequest, signedHeaders := createCanonicalRequest(r, payLoadHash, ctx)
	ctx.Application().Logger().Infof("canonicalRequest: %s", canonicalRequest)
	ctx.Application().Logger().Infof("signedHeaders: %s", signedHeaders)

	stringToSignByte := createStringToSign(amzDate, credentialScope, canonicalRequest)
	ctx.Application().Logger().Infof("stringToSign: %s", string(stringToSignByte))

	signatureKeyByte := createSignatureKey(secretKey, dateStamp, regionName, serviceName)
	ctx.Application().Logger().Infof("signatureKey: %s", toHexString(signatureKeyByte))

	signature := ghmac(signatureKeyByte, stringToSignByte)
	ctx.Application().Logger().Infof("signature: %s", toHexString(signature))

	authorization := algorithm + " Credential=" + accessKey + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + toHexString(signature)
	r.Header.Set("Authorization", authorization)
}
