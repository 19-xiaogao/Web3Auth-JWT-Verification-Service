# Web3Auth JWT Verification Service

## 🚀 Overview

This is a Go-based microservice for verifying Web3Auth JWT tokens and validating app public keys. The service provides a secure endpoint for token authentication and wallet verification.

## ✨ Features

- 🔐 JWT Token Verification
- 🔍 JWKS (JSON Web Key Set) Dynamic Fetching
- 🧊 App Public Key Validation
- 💻 RESTful Verification Endpoint

## 📦 Prerequisites

- Go 1.18+
- External dependencies:
    - `github.com/MicahParks/keyfunc/v2`
    - `github.com/golang-jwt/jwt/v5`

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/19-xiaogao/Web3Auth-JWT-Verification-Service.git

# Navigate to project directory
cd Web3Auth-JWT-Verification-Service

# Download dependencies
go mod download
```

