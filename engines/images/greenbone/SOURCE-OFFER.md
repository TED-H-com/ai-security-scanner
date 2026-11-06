# Greenbone engine corresponding source

The `ai-security-scanner` Greenbone engine image redistributes GPL-covered
software and the source-form Greenbone Community Feed. This notice identifies
the exact corresponding-source material shipped in the image.

| Component | Distributed revision | Corresponding source in the image |
| --- | --- | --- |
| Greenbone OpenVAS Scanner / `openvasd` | `cbd9081531ea6602bea7356aa371200979c1e961` (`23.52.9`) | `/usr/share/source/openvas-scanner/openvas-scanner-23.52.9.tar.gz` |
| Greenbone Community Feed | `a2e53c2e30f1fa5408369cb5cf99653a3e08e9df` (`202611060607-community`) | The executable NASL source, metadata, checksums, signature, and licenses are installed directly at `/opt/greenbone/feed` |
| Greenbone Notus data | `202611060538` | The source-form advisory/product data and licenses are installed at `/opt/greenbone/notus` |
| ai-security-scanner Greenbone launcher and build recipe | image source revision | `/usr/share/source/ai-security-scanner-greenbone/` |

The upstream source archives are checksum-locked in the included Dockerfile.
The scanner archive SHA-256 is
`ea798d3dcf2ca43b93be9bee9b644c699632226e5fa7659dbe40f6f4bd128f63`.
The Greenbone launcher contains the bounded SOCKS5 relay implementation used
by the image, so no opaque or preloaded network shim is part of the runtime.

For at least three years after the last distribution of this image, any third
party may request any additional machine-readable Corresponding Source needed
for a GPL-covered binary in this image by opening a public issue at
<https://github.com/teddashh/ai-security-scanner/issues>. It will be provided
for no more than the reasonable physical cost of conveying the source.
