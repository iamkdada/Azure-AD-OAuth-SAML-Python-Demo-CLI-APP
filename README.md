# dada-cli

DADA CLI is a CLI tool designed for testing the operation and features of Entra ID (Azure Active Directory). It enables the verification of functionalities in app registrations and enterprise applications, particularly focusing on SAML and OAuth 2.0.


## Features

- OAuth 2.0, Open ID Connect
  - You can experience the Authorization Code Flow and Client Credentials Flow.
  - Display and decode the obtained access tokens and ID tokens, enabling you to inspect their contents.
  - Use of simple Graph API operations to experience Continuous Access Evaluation (CAE).
  - Lmoad a certificate file and create a JWT assertion.
  
  By utilizing these features, you can easily verify the information and functionalities included in the token claims within Entra ID."

- SAML
  - You can easily experience SAML Single Sign-On (SSO) in Entra ID.
  - Generates SAML requests and decodes and displays SAML responses.
  - The command options allow you to specify the SAML request signature, Authentication Context, and Name ID Format.

  It allows you to easily test how Entra ID behaves when each of these settings is implemented."

## Installation

1. Installation
    ```bash
    $ git clone https://github.com/iamkdada/dada-cli.git
    $ cd dada-cli
    $ python3 -m venv venv
    $ pip3 install -r requirements.txt
    $ mkdir .dada
    $ export PATH="$PATH:$PWD/src"
   ```
2. Setting env file
   
   Place the following in a config.env file under the .dada directory.
   ```bash
    CLIENT_ID=<Application ID>
    TENANT_ID=<Your Tenant ID>
    AUTH_CODE_AT=
    AUTH_CODE_IT=
    AUTH_CODE_RT=
    CAE_CLAIMS_CHALLENGE=
    CLIENT_CREDENTIAL_AT=
    PRIVATE_KEY=
    PUBLIC_KEY=
    CLIENT_SECRET=
    ENTITY_ID=
    SAML_RESPONSE=
   ```
3. 
  ```bash
  $ export DADA_DATA_PATH="$PWD/.dada/config.env"
  ```


   plan to make improvements for easier installation.

## Example

- auth code token request
```bash
$ dada auth_code token_request
"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk2bEdrM0ZaenhSY1ViMkMzbkV~~~~~~~~~
"
```

- decode token
```bash
$ dada auth_code show --token id --decode
{
  "aud": "<GUID>",
  "exp": 1700021556,
  "iat": 1700017656,
  "iss": "https://login.microsoftonline.com/<tenant id>/v2.0",
  "name": "hoge hoge",
  "nbf": 1700017656,
  "oid": "<GUID>",
  "preferred_username": "hoge@*****.com",
  "rh": "0.AXwAji****************************",
  "sub": "XWFP_8f3rjEyjvlUzzTVB0v0W2I3DGxVn0*********",
  "tid": "GUID",
  "uti": "sBSSf-s2rkujr********",
  "ver": "2.0"
}
```

- saml reqest
```bash
$ dada saml saml_request --sign --force-authn
"
decode saml resuponse
"
```
