# Changelog

## 0.2.0 (2020-08-27)

* Rename `SecurityParams::discovery()` to `SecurityParams::for_discovery()`.
* Add wrapper around traits needed for digest algorithms. This simplifies specifying trait bounds.
* Use padding scheme described in RFC 3414. The previous padding scheme caused failures when trying to unpad the
  encrypted scoped PDU.
* Add `WithLocalizedKey` trait to generically create types with a localized key.
* Change `engine_boots` and `engine_time` type to `u32`.
* Change privacy keys 'salt' type to unsigned integer.

## 0.1.0 (2020-07-19)

Initial release.
