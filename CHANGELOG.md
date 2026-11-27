# Changelog

## [Unreleased]

### Added

- `ConnRequest.SetReceiverLatency` and `ConnRequest.SetPeerLatency` let a
  listener set the latency of a single connection request before `Accept()`,
  in place of its own config. Values are clamped to 0-65,535 ms, the range of
  the handshake field.

### Fixed

- Honor received DROPREQ ranges in live mode so the receiver stops requesting
  packets the sender has dropped and can acknowledge past those gaps without
  waiting for a later packet's playout time. Keep already received packets
  scheduled for delivery and bound pending drop metadata.
- Remove accepted DROPREQ ranges from pending reorder losses and exclude them
  when registering later gaps, preserving the TTL of other missing packets.
- Drop packets that can't be decrypted and unencrypted packets on an encrypted
  connection instead of delivering them, and count them as dropped, as libsrt does.
