# Third-party notices: Greenbone managed engine

This image contains these principal third-party works:

- Greenbone OpenVAS Scanner 23.52.9, revision
  `cbd9081531ea6602bea7356aa371200979c1e961`, under GPL-2.0. Its license and
  complete pinned source archive are shipped in the image.
- Greenbone Community Feed snapshot `202611060607-community`, revision
  `a2e53c2e30f1fa5408369cb5cf99653a3e08e9df`. The feed declares
  `(GPL-2.0-only or GPL-2.0-or-later or GPL-3.0-only) AND ODbL-1.0`; its NASL
  source, database, license texts, signed checksum manifest, and signature are
  included at `/opt/greenbone/feed`.
- Greenbone Notus generated data, revision `202611060538`. The distributed data includes
  its GPL-2.0 and ODbL-1.0 license notices at `/opt/greenbone/notus`.
- Debian and other system packages retained from the pinned official
  Greenbone scanner image. Their package copyright notices remain under
  `/usr/share/doc`.

The wrapper source is part of ai-security-scanner and is distributed under the
repository's Apache-2.0 license. This notice is informational and does not
replace any component's license text.
