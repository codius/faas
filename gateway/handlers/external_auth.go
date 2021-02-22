package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type RequestNamespace int

const (
	NoNamespace RequestNamespace = iota
	NamespaceInBody
	NamespaceInQueryParam
)

// MakeExternalAuthHandler make an authentication proxy handler
func MakeExternalAuthHandler(next http.HandlerFunc, upstreamTimeout time.Duration, upstreamURL string, passBody bool, reqNamespace RequestNamespace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)

		copyHeaders(req.Header, &r.Header)

		switch reqNamespace {
		case NamespaceInBody:
			nsBody := struct{ Namespace string }{}

			if r.Body != nil {
				defer r.Body.Close()
			}

			body, _ := ioutil.ReadAll(r.Body)
			err := json.Unmarshal(body, &nsBody)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Printf("ExternalAuthHandler: %s", err.Error())
				return
			}

			// Reconstruct Body
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

			req.Header.Add("X-Namespace", nsBody.Namespace)
		case NamespaceInQueryParam:
			q := r.URL.Query()
			namespace := q.Get("namespace")
			req.Header.Add("X-Namespace", namespace)
		}

		deadlineContext, cancel := context.WithTimeout(
			context.Background(),
			upstreamTimeout)

		defer cancel()

		res, err := http.DefaultClient.Do(req.WithContext(deadlineContext))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Printf("ExternalAuthHandler: %s", err.Error())
			return
		}

		if res.Body != nil {
			defer res.Body.Close()
		}

		if res.StatusCode == http.StatusOK {
			next.ServeHTTP(w, r)
			return
		}

		copyHeaders(w.Header(), &res.Header)
		w.WriteHeader(res.StatusCode)

		if res.Body != nil {
			io.Copy(w, res.Body)
		}
	}
}
