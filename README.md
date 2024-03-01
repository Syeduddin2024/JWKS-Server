## JWKS Server

This project implements a RESTful JWKS server that provides public keys for verifying JSON Web Tokens (JWTs). The server also supports key expiry, an authentication endpoint, and the issuance of JWTs with expired keys based on a query parameter.

## Features

- RSA key pair generation with unique identifiers (kid) and expiry timestamps
- RESTful JWKS endpoint serving public keys in JWKS format
- /auth endpoint for issuing unexpired, signed JWTs on POST requests
- Support for issuing JWTs signed with expired keys based on the "expired" query parameter

## Getting Started

1. Install the required packages:
   ```
   pip install cryptography jwt
   ```
2. Run the server:
   ```
   python server.py
   ```
   The server will start on `localhost:8080`.

## API Endpoints

### /.well-known/jwks.json

Returns the JSON Web Key Set (JWKS) containing the public keys with unique identifiers (kid) and expiry timestamps. Only serves keys that have not expired.

#### Example Request

```
GET /.well-known/jwks.json HTTP/1.1
Host: localhost:8080
```

#### Example Response

```json
{
  "keys": [
    {
      "kid": "abc123",
      "kty": "RSA",
      "use": "sig",
      "n": "..."
      "e": "..."
    },
    {
      "kid": "def456",
      "kty": "RSA",
      "use": "sig",
      "n": "..."
      "e": "..."
    }
  ]
}
```

### /auth

Returns an unexpired, signed JWT on a POST request. If the "expired" query parameter is present, issues a JWT signed with the expired key pair and the expired expiry.

#### Example Request

```
POST /auth?expired=true HTTP/1.1
Host: localhost:8080
```

#### Example Response

```
HTTP/1.1 200 OK
Content-Type: application/jwt

eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ. ...
```

## Testing

To run the unit tests, simply execute:

```
python test.py
```

The tests will validate the generation of JWTs with both unexpired and expired keys, as well as the JWKS endpoint.

## Built With

- [cryptography](https://cryptography.io/) - A Python library for cryptographic recipes and primitives.
- [jwt](https://pyjwt.readthedocs.io/en/stable/) - JSON Web Token implementation in Python.
- [sqlite3](https://docs.python.org/3/library/sqlite3.html) - A DB-API 2.0 interface for SQLite databases.
