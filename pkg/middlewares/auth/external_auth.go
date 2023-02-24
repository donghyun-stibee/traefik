package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	goauth "github.com/abbot/go-http-auth"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/tracing"
	"io"
	"net/http"
	"time"
)

const externalTypeName = "ExternalAuthType"

type Payload struct {
	Userid   string `json:"userid"`
	Password string `json:"password"`
}

type externalAuth struct {
	address     string
	next        http.Handler
	payload     Payload
	headerField string
	name        string
	client      http.Client
	auth        *goauth.BasicAuth
}

func NewExternal(ctx context.Context, next http.Handler, config dynamic.ExternalAuth, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, externalTypeName).Debug().Msg("Creating middleware")

	ea := &externalAuth{
		address: config.Address,
		next:    next,
		name:    name,
	}
	ea.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	ea.auth = &goauth.BasicAuth{Realm: defaultRealm}

	return ea, nil
}

func (e *externalAuth) GetTracingInformation() (string, ext.SpanKindEnum) {
	return e.name, ext.SpanKindRPCClientEnum
}

func (e *externalAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), e.name, externalTypeName)
	payload := Payload{}

	user, password, ok := req.BasicAuth()
	if !ok {
		logger.Debug().Msg("Authentication failed")
		tracing.SetErrorWithEvent(req, "Authentication failed")
		e.auth.RequireAuth(rw, req)
		return
	}
	payload.Userid = user
	payload.Password = password

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Debug().Msg("Payload marshalling failed")
		tracing.SetErrorWithEvent(req, "Payload marshalling failed")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	buff := bytes.NewBuffer(body)

	externalReq, err := http.NewRequest(http.MethodPost, e.address, buff)
	tracing.LogRequest(tracing.GetSpan(req), externalReq)
	if err != nil {
		logMessage := fmt.Sprintf("Error calling %s. Cause %s", e.address, err)
		logger.Debug().Msg(logMessage)
		tracing.SetErrorWithEvent(req, logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	tracing.InjectRequestHeaders(req)

	externalReq.Header.Set("Content-Type", "application/json")
	externalResponse, externalErr := e.client.Do(externalReq)
	if externalErr != nil {
		logMessage := fmt.Sprintf("Error calling %s. Cause: %s", e.address, externalErr)
		logger.Debug().Msg(logMessage)
		tracing.SetErrorWithEvent(req, logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	respBody, readError := io.ReadAll(externalResponse.Body)
	if readError != nil {
		logMessage := fmt.Sprintf("Error reading body %s. Cause: %s", e.address, readError)
		logger.Debug().Msg(logMessage)
		tracing.SetErrorWithEvent(req, logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer externalResponse.Body.Close()

	logger.Debug().Msg(string(respBody))

	if externalResponse.StatusCode != http.StatusOK {
		logger.Debug().Msgf("Remote error %s. StatusCode: %d", e.address, externalResponse.StatusCode)
		e.auth.RequireAuth(rw, req)
		return
	}

	req.RequestURI = req.URL.RequestURI()
	e.next.ServeHTTP(rw, req)
}
