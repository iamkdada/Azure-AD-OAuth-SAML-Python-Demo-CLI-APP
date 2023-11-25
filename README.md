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
      ```
      #### Command Prompt
      ```bash
      set PATH=%PATH%;%CD%\src
      ```

   Plan to make improvements for easier installation.

## App Setting

### OIDC, OAuth App
#### Entra ID (Azure AD)
   1. Browse to [Azure Portal]>[Microsoft Entra ID]>[App Registrations] and select New registration.
   2. Enter a Name for your application, for example dada-cli-oidc. Users of your app might see this name, and you can change it later.
   3. Select bellow
      - Account Type : "Accounts in this organizational directory only"
      - Platform"Public client/native (mobile & desktop)"
      - Redirect uri : http://localhost
   4. Select Register to create the application.

#### DADA CLI
   1. Setting Tenant ID & Client ID
      ```bash
      dada configure --tenant-id "<Your Tenant ID>" --client-id "Registered Application ID"
      ```
   2. Let's token request
      ```bash
      dada auth-code token-request
      ```

### SAML App
#### Entra ID (Azure AD)
   1. Browse to [Azure Portal]>[Microsoft Entra ID]>[Enterprise Application] and select New application.
   2. Select Create your own application
   3. Enter a Name for your application, for example dada-cli-saml. Users of your app might see this name, and you can change it later.
   4. Select "Integrate any other application you don't find in the gallery (Non-gallery)" and select Create
   5. Browse to [Single sign-on]>[SAML] and select Edit.
   6. Add identifier, for example dada.
   7. Add reply URL as http://localhost

#### DADA CLI
   1. Setting Tenant ID & Client ID
      ```bash
      dada configure --tenant-id "<Your Tenant ID>" --entity-id "Registered Application Entity ID"
      ```
   2. Let's saml request
      ```bash
      dada saml saml_request
      ```

## Example

- auth code token request
   ```bash
   $ dada auth-code token-request
   "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk2bEdrM0ZaenhSY1ViMkMzbkV~~~~~~~~~
   "
   ```

- decode token
   ```bash
   $ dada auth-code show --token id --decode
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
   $ dada saml saml-request --sign --force-authn
   "
   <decode saml resuponse>
   "
   ```
