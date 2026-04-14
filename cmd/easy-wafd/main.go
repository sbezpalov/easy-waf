package main

import "github.com/easy-waf/easy-waf/internal/bootstrap"

// Deprecated binary name: use easy-waf-api. Kept for compatibility with older unit files.
func main() {
	bootstrap.RunAPI()
}
