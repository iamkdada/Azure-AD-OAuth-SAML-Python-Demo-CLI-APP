# Command Reference

## General Command
- dada configure
  
  Configure the application information for the dada CLI.
    ```bash
    dada configure [--tenant-id]
                   [--client-id]
                   [--entity-id]
    ```
- dada logout

  Discard the token information and certificate information.
    ```bash
    dada logout
    ```

- dada credential
  
  Set up the application credentials.
  Credential information for a certificate allows registration of both a public key and a private key, but not just one of the two. Therefore, for SAML apps and client credential apps, either the same certificate information must be used, or if different certificates are to be used, this command must be utilized to update the certificate information before using the app

    ```bash
    dada credential [--path]
                    [--passphrase]
                    [--secret]
    ```
  ### Example

    Load the Pfx file and set the private key and public key."
    ```bash
    dada credential --path "./selfsigncert.pfx" --passphrase "password"
    ```
  
    Load and set the private key and public key separately.
    ```bash
    dada credential --path "./privatekey.pem"
    dada credential --path "./cert.pem"
    ```
  
    Set client secret.
    ```bash
    dada credential --secret "secret string"
    ```

- dada jwt-decode

  Decode jwt string.
  ```bash
  dada jwt-decode [--token]
  ```

  ### Example
    ```bash
    dada jwt-decode --token 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0ZaenhSY1ViMkMzbkVRN3N5SEpsWSJ9.eyJhdWQiOiI2ZTc0MTcyYi1iZTU2LTQ4NDMtOWZmNC1lNjZhMzliYjEyZTMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE1MzcyMzEwNDgsIm5iZiI6MTUzNzIzMTA0OCwiZXhwIjoxNTM3MjM0OTQ4LCJhaW8iOiJBWFFBaS84SUFBQUF0QWFaTG8zQ2hNaWY2S09udHRSQjdlQnE0L0RjY1F6amNKR3hQWXkvQzNqRGFOR3hYZDZ3TklJVkdSZ2hOUm53SjFsT2NBbk5aY2p2a295ckZ4Q3R0djMzMTQwUmlvT0ZKNGJDQ0dWdW9DYWcxdU9UVDIyMjIyZ0h3TFBZUS91Zjc5UVgrMEtJaWpkcm1wNjlSY3R6bVE9PSIsImF6cCI6IjZlNzQxNzJiLWJlNTYtNDg0My05ZmY0LWU2NmEzOWJiMTJlMyIsImF6cGFjciI6IjAiLCJuYW1lIjoiQWJlIExpbmNvbG4iLCJvaWQiOiI2OTAyMjJiZS1mZjFhLTRkNTYtYWJkMS03ZTRmN2QzOGU0NzQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhYmVsaUBtaWNyb3NvZnQuY29tIiwicmgiOiJJIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJIS1pwZmFIeVdhZGVPb3VZbGl0anJJLUtmZlRtMjIyWDVyclYzeERxZktRIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiZnFpQnFYTFBqMGVRYTgyUy1JWUZBQSIsInZlciI6IjIuMCJ9.pj4N-w_3Us9DrBLfpCt'
    ```

## dada auth-code
### token-request

  Obtain token using the authorization code flow.
  ```bash
  dada auth-code token-request [--scopes]
                               [--cae]
  ```
  - --scopes
    
    Specify the scope. If omitted, the scope 'openid email profile' will be specified.
  - --cae

    This is used to validate continuous access evaluation. For instructions on how to use it, please refer to the validation of continuous access evaluation."

###  show

  Display the obtained token.
  ```bash
  dada auth-code show [--token]
                      [--decode]
  ```

  #### Example
  ```bash
  dada auth-code show --token access --decode
  ```

  - --token

    Specify whether it is an access token or an ID token. 
    If not specified, the access token will be displayed.
  
  - --decode

    Decode the token and display it.

### graph-request

  Call Graph API using the obtained access token.
  ```bash
  dada auth-code graph-request [--url]
                               [--method]
                               [--ver]
                               [--body]
  ```
  #### Exmaple
  ```bash
  dada auth-code graph-request --url "users" --ver "beta"
  ```

  - --url
  
    Specify the URL path for the Graph API. If not specified, 'me' will be used as the default.
  - --method
  
    HTTP method. ex: GET, POST
  - --ver

    Specify the Graph API version.
    If not specified, 'v1.0' will be used as the default.
  - --body

    Specify the HTTP Request Body.

## dada client-cred

### token-request

  Obtain token using the client-credential flow.
  ```bash
  dada client-cred token-request [--scopes]
                                 [--cae]
  ```
  - --credential
    
    This option is mandatory. It specifies whether to use a certificate or a secret for credentials. Specify 'cert' or 'secret' as the value.
  - --secret
  
    Specify the secret string to be used for credentials. 
    If this option is not used, the previously used secret will be utilized.
    Additionally, the secret of this app will be updated to the specified value.
    
  - --pfx

    Specify the pfx file path.
    If this option is not used, the previously used certificate will be utilized.
    Additionally, private key and public key of this app will be updated.

  - passphrase

    Specify the pfx file passphrase.

###  show

  Display the obtained an access token.
  ```bash
  dada client-cred show [--decode]
  ```

  - --decode

    Decode the token and display it.

### graph-request

  Call Graph API using the obtained access token.
  ```bash
  dada client-cred graph-request [--url]
                               [--method]
                               [--ver]
                               [--body]
  ```
  #### Exmaple
  ```bash
  dada client-cred graph-request --url "users" --ver "beta"
  ```

  - --url
  
    Specify the URL path for the Graph API. If not specified, 'users' will be used as the default.
  - --method
  
    HTTP method. ex: GET, POST
  - --ver

    Specify the Graph API version.
    If not specified, 'GET' will be used as the default.
  - --body

    Specify the HTTP Request Body.

## dada credential
### thumbprint

  Obtain the Certificate fingerprint (SHA 1).
  ```bash
  ada credential thumbprint
  ```

### assertion

  Generate jwt assertion.
  ```bash
  dada credential assertion [--tenant-id]
                            [--client-id]
  ```

  - --tenant-id

    If omitted, the previously set tenant ID will be used.

  - --client-id
  
    If omitted, the previously set client ID will be used.

## dada saml
### dada saml saml-request

  Launch the browser and perform SAML authentication. If the authentication is successful, the SAML response will be displayed in XML format.
  ```bash
  dada saml saml-request [--sign]
                         [--force-authn]
                         [--name-id-format]
                         [--authn-context]
  ```

  - --sign

    If this option is specified, the SAML request will be signed. The signature will be performed using SHA256.
    The signature will be made using the private key registered with this app.

  - --force-authn

    If this option is specified, a SAML request with 'force-authn' set to True will be generated.
    

  - --name-id-format

    If this option is specified, a SAML request with 'force-authn' set to True will be generated.

  - --authn-context

    By specifying this option, you can add an Authn Context to the SAML request. For example, specify urn:oasis:names:tc:SAML:2.0:ac:classes:X509.


### dada saml show

  Display the obtained SAML response.
  ```bash
  dada saml show
  ```
