# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.4] - 2023-10-18
### Changed
- Added lab cluster certificate

## [1.2.1] - 2020-11-18
### Changed
- URL encode spaces in scope in order for Mac OS Big Sur to recognize the authorization URL as a proper URL.

## [1.2.0] - 2020-08-11
### Changed
- Add `tbac` and `email` scope to token server authorization request, which will result in an ID token containing only
  claims (groups specifically) relevant to TBAC. This often cuts the returned token size in half or more.
- Will now verify certificates for any known Bisnode cluster.

## [1.1.1] - 2020-05-29
### Changed
- kubectl-login will now exit after 10 minutes of idling. This in order to prevent the program from staying in the
  background if left unattended.
- Added a sleep in the main loop to avoid hogging the CPU while active.

## [1.1.0] - 2020-02-12
### Changed
- Token is now stored outside of `KUBECONFIG` to avoid it being sent when expired, as described in the kubernetes issue
  [#87369](https://github.com/kubernetes/kubernetes/issues/87369).

## [1.0.1] - 2020-01-22
### Changed
- Fixed bug in `kubectl-login whoami` where team belonging would be blank in output.
- Fixed bug in `kubectl-login whoami` that cut out parts of longer team names.

## [1.0.0] - 2020-01-21
### Added
- First release!
