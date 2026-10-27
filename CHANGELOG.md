# Changelog

## [Unreleased]

### Fixed

- Honor received DROPREQ ranges in live mode so the receiver stops requesting
  packets the sender has dropped and can acknowledge past those gaps without
  waiting for a later packet's playout time. Keep already received packets
  scheduled for delivery and bound pending drop metadata.
