// Standalone test helper: exercise Go's system certificate validation inside
// the fence. No custom roots, client credentials or insecure TLS override.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: 45 * time.Second}
	response, err := client.Get("https://github.com/")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, response.Status)
		os.Exit(1)
	}
	fmt.Println("go-https-ok")
}
