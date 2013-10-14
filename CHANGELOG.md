## v0.1.2

* Add support for a custom callback to receive timeouts for the messager,
  eliminating the need to repeatedly poll every messager instance
  (particularly useful in servers).
* Increment the major component of the shared library version due to ABI
  compatibility break.

## v0.1.1

* Include `check_extras.h` in `EXTRA_DIST` so `make check` executes correctly.

## v0.1.0

* Initial release.
