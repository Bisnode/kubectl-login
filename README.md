# kubectl-login

**NOTE - This application is currently in alpha. Testers wanted!**


## Motivation - 2FA authentication for kubectl

In order to fulfill the requirement of multi factor authentication (MFA) for admin like access to any production 
resources, our current certificate based solution for kubernetes authentication will have to be replaced. As kubernetes 
supports authentication through the OpenID Connect (OIDC) standard we will naturally use our Common Login component for 
issuing ID tokens for that purpose.

The Common Login team and internal IT have worked together to build a connector that will allow us to use the regular 
ADFS authenticator. This has many benefits, including:

- Well known by all Bisnode employees. This is the same authenticator that is used to login to any Office 365 products.
- 2FA built in, using either SMS or Microsoft’s Authenticator (the latter highly recommended for heavy use).
- Single Sign-On (SSO). Since you already use the ADFS authenticator for logging in to other services, chances are good 
  that you’ll already be authenticated, thus letting you proceed without having to login again.

To authenticate yourself for using kubectl you may follow the steps below:


## Installation

**Prerequisites:** kubectl version 12 or higher.

For authenticating using OIDC the very first time it is recommended to first clear your current kubectl client 
configurations. These are found in the `$HOME/.kube/` directory and are named `config.[environment]` per respective 
environment. Remove them so that you may start from a clean state.

With that out of the way, download the kubectl-login binary for your operating system and place it in your `$PATH`. 
This binary is a plugin for kubectl, and is required to be in your `$PATH` or kubectl won’t find it.

Once in your `$PATH` you may now use the plugin by issuing `kubectl login`. Before doing that you must however 
initialize new “kubeconf” configurations for each environment. You may do this by issuing `kubectl login --init all`. 
This will create new `config.[environment]` files in your `$HOME/.kube/` directory prepared for OIDC authentication.
You can also initiate a single environment by providing it's name, e.g. `kubectl login --init dev`


## Usage instructions

- With the config in place. Any kubectl commands you provide (like `kubectl get pods`) will now automatically open your 
  preferred web browser and the ADFS authenticator. Login as you normally would, and once done you may close the browser 
  tab.
- The ID token issued from the authentication has now been stored in your kubectl configuration and is usable for 8 
  hours before you’ll need to login again.

Note that ID tokens are stored and used _per environment_. Moving from one kubernetes environment to another means 
you’ll need to re-authenticate. Chances are however pretty good that the ADFS server remembers you from your last 
authentication (regardless of environment, there’s only one ADFS after all), thus authentication you without you having 
to login again.


## Developing and building

**Prerequisites:** any semi-recent version of Go.

    git clone ssh://git@buildtools.bisnode.com:7999/bcmn/kubectl-login.git
    cd kubectl-login
    export $GO111MODULE=auto # If not set already
    go build

The `kubectl-login` binary will now be in your current directory. Replace the one on your `$PATH` with the one you built
to try it out.


## FAQ

> Is it possible to initiate login without issuing another kubectl command?

Yes, simply use `kubectl login`.
 
> Can I force a new token to be issued if I already have one stored?

Yes. Use `kubectl login —force`.

> How can I use kubectl inside a Docker container where there is no web browser?

Mount the `~/.kube/` directory into your container and initialize login from outside of it using `kubectl login`. 
The token stored after authentication is now available for use inside the container.

> I have a problem or an idea for an improvement!

Great! Ping me (Anders Eknert) if you’d like to discuss it, or submit a PR if you’re up for some Go hacking.


