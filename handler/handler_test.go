package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerReturns405OnGetRequest(t *testing.T) {
	rr := testRequest("GET", "/redirect", nil, nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Plain GET request should return 405 Method Not Allowed, got %v", rr.Code)
	}

	if rr.Body.String() != "" {
		t.Errorf("Plain GET request should return empty body, got %v", rr.Body.String())
	}
}

func TestHandlerReturns400OnPostWithNoOrWrongContentType(t *testing.T) {
	rr := testRequest("POST", "/redirect", nil, nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST request with no Content-Type should be a 400 Bad Request, got %v", rr.Code)
	}

	headers := map[string]string{"Content-Type": "text/plain"}
	rr = testRequest("POST", "/redirect", headers, nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST request with Content-Type other than application/json should be a 400 Bad Request, got %v",
			rr.Code)
	}
}

// Since headers are 99% likely to be single occurrence/value we postpone
// the standards multi-value ceremony until we pass them to the http module
func normalizeHeaders(headers map[string]string) map[string][]string {
	target := make(map[string][]string)
	for key, value := range headers {
		target[key] = []string{value}
	}
	return target
}

func testRequest(method, target string, headers map[string]string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Header = normalizeHeaders(headers)
	rr := httptest.NewRecorder()
	s := IDTokenWebhookHandler{}
	s.ServeHTTP(rr, req)

	return rr
}
