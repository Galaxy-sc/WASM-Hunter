package main

import (
	"net/http"
	"syscall/js"
)

func main() {
	stripeKey := "sk_live_abcdefghijklmnopqrstuvwx"
	discordToken := "MTIzNDU2Nzg5MDEyMzQ1Njc4.Gq-123.abcdefghijklmnopqrstuvwxyz12345"
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
	
	absoluteURL := "https://securitymgmt.staging.unifiedapis.example.com"
	postgresURI := "postgresql://dbuser:secretpass@database.internal.corp:5432/webapp"

	performNativeFetch(absoluteURL, jwtToken, stripeKey)
	buildGoRequest(absoluteURL, discordToken, postgresURI)
}

func performNativeFetch(url, jwt, stripe string) {
	headers := map[string]interface{}{
		"Authorization": "Bearer " + jwt,
		"X-Stripe-Key":  stripe,
	}

	options := map[string]interface{}{
		"method":  "GET",
		"headers": headers,
	}

	js.Global().Call("fetch", url, js.ValueOf(options))
}

func buildGoRequest(url, discord, dbURI string) {
	req, err := http.NewRequest("POST", url, nil)
	if err == nil {
		req.Header.Set("Authorization", discord)
		
		req.Header.Set("X-DB-Conn", dbURI)
	}
}