# Licensing policy

`xavi-browser-js` is dual-licensed under **MIT OR Apache-2.0**.

## Core

All source distributed as part of the core package is first-party unless explicitly documented
otherwise. Runtime dependencies are intentionally avoided.

## Browser sandbox / WASM images

Distributable sandbox images must be first-party and declare exactly:

- `MIT OR Apache-2.0`

MIT-only or Apache-2.0-only third-party artifacts may be useful as external build tools or optional integrations, but they are not accepted as distributable Xavi sandbox images. Our shipped image/module code is dual-licensed under both choices.

The project will not redistribute a converted general-purpose container image merely because the
conversion tool is permissively licensed. The license of the converter does not relicense the
container filesystem, kernel, emulator, standard library, or other guest contents.

External tools such as `container2wasm` may be used during development or experimentation, but
are not runtime dependencies and their example/guest images are not part of this distribution.

## Image authority

Every image registered for sandbox execution has immutable identity metadata: image ID, content
digest, first-party flag, declared license, build recipe, and allowed capabilities. Learned state
may choose among approved images but cannot alter their identity, license, or permissions.
