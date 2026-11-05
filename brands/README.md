# Brands (white-label builds)

Every folder here is one brand of the app. All brands share the same code; a build only swaps the name,
package id, Telegram bot, channel and logo. Fixing a bug or adding a feature therefore reaches every brand.

To add a brand create `brands/<id>/` with:

* `brand.json`
  * `id`: folder name, lower case
  * `name`: app name shown under the icon
  * `applicationId`: unique package id, e.g. `ir.ertebatgoostar.brand2` (never change it afterwards: it is what
    makes updates install over the old version)
  * `apkPrefix`: letters/digits, unique, used in the APK file names (`<apkPrefix>_<version>_<abi>.apk`) and by the
    in-app updater to find its own files
  * `bot`: bot username without `@`
  * `channel`: channel link
  * `replaceIcon`: `true` (default) to build the launcher icon and the faint background logo from the logo file
  * `iconBackground`: optional launcher background colour, default `#000000`
* `logo.png` (or `logo.jpg`): square logo, at least 512x512.

Build: Actions -> "Build APK" -> `release_tag` and `brands` (`egn` = test on the EGN brand only, `all` = every
folder, or a list such as `egn,brand2`). Each brand's APKs (arm64-v8a, armeabi-v7a, universal) are added to the
release. A brand's app only offers updates from releases that contain its own files.
