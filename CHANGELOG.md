# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
