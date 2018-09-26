3.0.5
-----

Changes:

* Make `rake` development dependency not runtime

3.0.4
-----

Fixed:

* Compilation on Archlinux

3.0.3
-----

Fixed:

* ~Compilation on Archlinux~


3.0.2
-----

Fixed:

* ~~Compilation on Archlinux~~


3.0.1
-----

Fixed:

* Windows support was broken in 3.0.0


3.0.0
-----

Breaking Changes:

* None

Added:

* Updated of core scrypt ext code: https://github.com/pbhogan/scrypt/pull/53
* Support for platforms other than x86 such as ARM

2.1.1
-----

Changes:

* Uses more secure defaults: Increased max_mem from 1MB to 16MB, and salt_len from 8 to 32 bytes.
* See discussion at https://github.com/pbhogan/scrypt/issues/25

2.0.1
-----

Changes:
* Adds a `:cost` option for specifying a cost string (e.g. `'400$8$19$'`) from the `calibrate` method
  (https://github.com/pbhogan/scrypt/commit/95ce6e3e37f4b2e8681a544713bfe783d2d69466)

2.0.0
-----

Breaking Changes:

* `SCrypt::Password#hash` has been renamed to `#checksum`
  (https://github.com/pbhogan/scrypt/commit/a1a60e06ec9d863c3156ac06fda32ce82cddd759)

