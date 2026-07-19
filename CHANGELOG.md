# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-07-19

### Added

- Optional on-disk consensus cache. Point `TorConfig(cache_dir=...)` at a directory
  to reuse a verified consensus across processes and skip the consensus fetch on a
  warm start. The cached file is re-verified on every load, so it is trusted no more
  than a freshly fetched consensus; leaving `cache_dir` unset keeps all directory
  state in memory and writes nothing to disk.

## [1.0.0] - 2026-07-16

Initial release: a pure-Python Tor client with v3 onion-service support and a
`requests`-compatible API.

[1.0.1]: https://github.com/SafwanLjd/torquests/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/SafwanLjd/torquests/releases/tag/v1.0.0
