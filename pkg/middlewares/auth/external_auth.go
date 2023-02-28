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
	"strings"
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
	entryPoints []string
}

func NewExternal(ctx context.Context, next http.Handler, config dynamic.ExternalAuth, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, externalTypeName).Debug().Msg("Creating middleware")

	ea := &externalAuth{
		address:     config.Address,
		next:        next,
		name:        name,
		entryPoints: config.EntryPoints,
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
	needAuth := false

	for _, ep := range e.entryPoints {
		url := strings.Split(req.URL.RequestURI(), "?")[0]
		//logger.Debug().Msgf("request to %s || entryPoints %s", url, ep)

		// pattern match
		if strings.Contains(ep, "*") {
			nep := strings.Replace(ep, "/*", "", -1)
			//logger.Debug().Msgf("entry point contains * (%s), url %s new entry point %s", ep, url, nep)
			if strings.Contains(url, nep) {
				needAuth = true
				logStr := fmt.Sprintf("request to entry point [%s] which need to be authenticated", ep)
				logger.Debug().Msg(logStr)
			}
		} else {
			//logger.Debug().Msgf("url %s entry point %s", url, ep)
			// exact match
			if url == ep {
				needAuth = true
				logStr := fmt.Sprintf("request to entry point [%s] which need to be authenticated", ep)
				logger.Debug().Msg(logStr)
			}
		}
	}

	if !needAuth {
		e.next.ServeHTTP(rw, req)
		return
	}

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

	_, readError := io.ReadAll(externalResponse.Body)
	if readError != nil {
		logMessage := fmt.Sprintf("Error reading body %s. Cause: %s", e.address, readError)
		logger.Debug().Msg(logMessage)
		tracing.SetErrorWithEvent(req, logMessage)

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer externalResponse.Body.Close()

	if externalResponse.StatusCode != http.StatusOK {
		logger.Debug().Msgf("Remote error %s. StatusCode: %d", e.address, externalResponse.StatusCode)
		e.auth.RequireAuth(rw, req)
		return
	}

	req.RequestURI = req.URL.RequestURI()
	e.next.ServeHTTP(rw, req)
	return
}
