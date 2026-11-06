# TruffleHog corresponding source

The managed TruffleHog image is built from and carries the exact
AGPL-3.0 source archive for commit
`ea68ca03c865c5f324e86e849ced20ed3cf9dbbb` at
`/usr/share/source/trufflehog-source.tar.gz`. The project Dockerfile and fixed
launcher used to build and run it are also present in the public
`ai-security-scanner` repository.

The launcher exposes filesystem scanning only. It always supplies
`--no-verification`, `--no-verification-cache`, and `--no-update`; the managed
runtime supplies no network path.
