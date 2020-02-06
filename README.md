# kubectl-login
![](https://github.com/Bisnode/kubectl-login/workflows/build/badge.svg)

OpenID Connect (OIDC) authentication plugin for kubectl. Built specifically for requirements at Bisnode, but given some 
minor modification most likely useful in other contexts too.

Notable differences compared to the commonly found OIDC authentication plugins for kubectl:

- Does not make use of the OAuth2/OIDC code flow, and hence does not try to refresh issued ID tokens. Since the 
  application is distributed among a large group of developers, attempting to keep secrets inside of the app is not
  meaningful.
- The OpenID Connect specification does not require the ID token to be part of the 
  [refresh token response](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse), and in fact in
  many implementations isn't.
- Instead opts for the simpler implicit flow, using the OIDC specific `form_post` response mode to transfer the issued 
  ID token to the kubectl client plugin. Since all access to the kubernetes API is expected to be restricted to internal
  clients (through network policies and whatnot), 
- Configuration compiled with executable - no external configuration files. This naturally requires the program to be 
  compiled for its target environment.
- Not using the code flow and refresh capabilities requires long lived ID tokens. This is normally _not_ a problem if 
  a) access is restricted to internal clients and b) the ID tokens are issued with for this purpose alone and useless
  for authentication purposes in other contexts. Limiting the plugin to ID tokens issued for this client is easily 
  accomplished by setting the `--oidc-required-claim` flag to something like `aud=kubectl-login` or some other unique
  attribute on the client assigned for the purpose.
  
If you find yourself having similar requirements or goals as these - this plugin might be a good starting point for you.

## Installation

**Prerequisites:** kubectl version 12 or higher.

For authenticating using OIDC the very first time it is recommended to first clear your current kubectl client 
configurations. These are found in the `$HOME/.kube/` directory and are named `config.[environment]` per respective 
environment. Remove them so that you may start from a clean state.

With that out of the way, download the kubectl-login binary for your operating system and place it in your `$PATH`. 
This binary is a plugin for kubectl, and is required to be in your `$PATH` or kubectl won’t find it.

Once in your `$PATH` you may now use the plugin by issuing `kubectl login`. Before doing that you must however 
initialize new kubeconf configurations for each environment. You may do this by issuing `kubectl login --init all`. 
This will create new `config.[environment]` files in your `$HOME/.kube/` directory prepared for OIDC authentication.
You can also initiate a single environment by providing it's name, e.g. `kubectl login --init dev`

## Usage instructions

- With the config in place. Any kubectl commands you provide (like `kubectl get pods`) will now automatically open your 
  preferred web browser and the authenticator setup for the configured client. Login as you normally would, and once 
  done you may close the browser tab.
- The ID token issued from the authentication has now been stored in your kubectl configuration and is usable for X
  hours before you’ll need to login again.

Note that ID tokens are stored and used _per environment_. Moving from one kubernetes environment to another means 
you’ll need to re-authenticate. Chances are however pretty good that the authentication server remembers you from your 
last authentication (naturally depending on how that is configured), thus authentication you without you having 
to login again.

## Developing and building

**Prerequisites:** any semi-recent version of Go.

    git clone git@github.com:Bisnode/kubectl-login.git
    cd kubectl-login
    export $GO111MODULE=auto # If not set already
    go build

The `kubectl-login` binary will now be in your current directory. Replace the one on your `$PATH` with the one you built
to try it out.

### Adaptions

To modify this for use in a different environment, code in these places should be modified:

- Change the `ClusterIssuer` mapping function in `util.go` to point to your issuer and authorize endpoints.
- Update the `ContextToEnv` mapping function accordingly.
- Set the `authorizeParameters` in main.go to whatever values configured in your token server.

## FAQ

**Q:** Is it possible to initiate login without issuing another kubectl command?
**A:** Yes, simply use `kubectl login`

**Q:** Can I force a new token to be issued if I already have one stored?
**A:** Yes. Use `kubectl login —force`

**Q:** Can I somehow see the details (like username and groups) sent for use in authentication/authorization?
**A:** Yes, use kubectl login whoami. Or you may of course inspect the ID token manually (stored in your config found 
       in ~/.kube/).

**Q:** How can I use kubectl inside a Docker container where there is no web browser?
**A:** Mount the ~/.kube/ directory into your container and initialize login from outside of it using kubectl login. 
       The token stored after authentication is now available for use inside the container.

**Q:** The kubectl login command seems to open the default web browser - can I control that somehow?
**A:** Yes, set the KUBECTL_LOGIN_BROWSER environment variable to the name of the browser you'd like to use - like 
       "Google Chrome", "Safari", etc.
