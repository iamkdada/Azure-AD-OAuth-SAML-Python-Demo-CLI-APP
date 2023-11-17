# dada-cli

DADA CLI is a CLI tool designed for testing the operation and features of Entra ID (Azure Active Directory). It enables the verification of functionalities in app registrations and enterprise applications, particularly focusing on SAML and OAuth 2.0.


## Features

- OAuth 2.0, Open ID Connect
  - You can experience the Authorization Code Flow and Client Credentials Flow.
  - Display and decode the obtained access tokens and ID tokens, enabling you to inspect their contents.
  - Use of simple Graph API operations to experience Continuous Access Evaluation (CAE).
  - Load a certificate file and create a JWT assertion.
  
  By utilizing these features, you can easily verify the information and functionalities included in the token claims within Entra ID."

- SAML
  - You can easily experience SAML Single Sign-On (SSO) in Entra ID.
  - Generates SAML requests and decodes and displays SAML responses.
  - The command options allow you to specify the SAML request signature, Authentication Context, and Name ID Format.

  It allows you to easily test how Entra ID behaves when each of these settings is implemented."

## Installation

### WSL
  1. Installation
      ```bash
      $ git clone https://github.com/iamkdada/dada-cli.git
      $ cd dada-cli
      $ python3 -m venv venv
      $ pip3 install -r requirements.txt
      $ export PATH="$PATH:$PWD/src"
     ```
  2. DADA_DATA_PATH set above config.env.
     ```bash
     $ export DADA_DATA_PATH="$PWD/.dada/config"
     ```

### Windows
   1. Download this project
   2. Extract the downloaded project.
   3. Create a virtual environment at this project dir.
      ```bash
      > python -m venv venv
      ```
   4. Download the required libraries.
      ```bash
      > pip install -r requirements.txt
      ```
   5. Set up the environment variables.
      #### PowerShell 
      ```bash
      > $Env:PATH += ";$PWD\src"
      > $Env:DADA_DATA_PATH = "$PWD\.dada\config"
      ```
      #### Command Prompt
      ```bash
      set PATH=%PATH%;%CD%\src
      set DADA_DATA_PATH=%CD%\.dada\config
      ```

   Plan to make improvements for easier installation.

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

- saml request
   ```bash
   $ dada saml saml_request --sign --force-authn
   "
   decode saml resuponse
   "
   ```
