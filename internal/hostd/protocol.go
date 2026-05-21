package hostd

// Request is one privileged operation from easy-waf-api.
type Request struct {
	Argv []string `json:"argv"`
}

// Response is returned for each request.
type Response struct {
	OK     bool   `json:"ok"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Code   int    `json:"code"`
	Error  string `json:"error,omitempty"`
}
