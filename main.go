package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Wallet represents a single wallet object from the JWT payload
type Wallet struct {
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
}

// JWTClaims represents the claims in the decoded JWT
type JWTClaims struct {
	Wallets []Wallet `json:"wallets"`
}

func main() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// Extract idToken from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusBadRequest)
			return
		}
		idToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if idToken == "" {
			http.Error(w, "Invalid Authorization header format", http.StatusBadRequest)
			return
		}

		// Extract app_pub_key from the request body
		var requestBody struct {
			AppPubKey string `json:"appPubKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		appPubKey := strings.ToLower(requestBody.AppPubKey)

		// Fetch JWKS from Web3Auth
		jwksURL := "https://api-auth.web3auth.io/jwks"
		jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
			RefreshErrorHandler: func(err error) {
				// Optionally log JWKS refresh errors
				_, _ = os.Stderr.WriteString("JWKS fetch error: " + err.Error() + "\n")
			},
		})
		if err != nil {
			http.Error(w, "Failed to fetch JWKS: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer jwks.EndBackground()

		// Parse and verify the idToken
		token, err := jwt.Parse(idToken, jwks.Keyfunc, jwt.WithValidMethods([]string{"ES256"}))
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Token is not valid", http.StatusUnauthorized)
			return
		}

		// Extract and verify the claims
		var claims JWTClaims
		if claimsData, ok := token.Claims.(jwt.MapClaims); ok {
			claimsBytes, err := json.Marshal(claimsData)
			if err != nil {
				http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := json.Unmarshal(claimsBytes, &claims); err != nil {
				http.Error(w, "Failed to decode claims: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Invalid claims", http.StatusInternalServerError)
			return
		}

		// Check wallets for type "web3auth_app_key" and match app_pub_key
		verified := false
		for _, wallet := range claims.Wallets {
			if wallet.Type == "web3auth_app_key" && strings.ToLower(wallet.PublicKey) == appPubKey {
				verified = true
				break
			}
		}

		// Send the response based on the verification result
		if verified {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name": "Verification Successful"}`))
		} else {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"name": "Verification Failed"}`))
		}
	})

	// Start the server
	http.ListenAndServe(":8080", nil)
}
