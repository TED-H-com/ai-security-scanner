# TruffleHog corresponding source

The managed TruffleHog image is built from and carries the exact
AGPL-3.0 source archive for commit
`e76dff8a7e57d6df0c60ad8cbf5d5cba505a8fc9` at
`/usr/share/source/trufflehog-source.tar.gz`. The project Dockerfile and fixed
launcher used to build and run it are also present in the public
`ai-security-scanner` repository.

The launcher exposes filesystem scanning only. It always supplies
`--no-verification`, `--no-verification-cache`, and `--no-update`; the managed
runtime supplies no network path.
