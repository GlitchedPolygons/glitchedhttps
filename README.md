
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg?style=flat-square)](https://glitchedpolygons.github.io/glitchedhttps/files.html)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-brightgreen?style=flat-square)](https://github.com/GlitchedPolygons/glitchedhttps/blob/master/LICENSE)

# Glitched HTTPS
### Simple, lightweight and straight-forward way of doing HTTP(S) requests with the help of [ARM's open-source MbedTLS library](https://github.com/ARMmbed/mbedtls).

> ᐳᐳ  Check out the API docs [here on github.io](https://glitchedpolygons.github.io/glitchedhttps/files.html)

### How to clone

`git clone --recursive https://github.com/GlitchedPolygons/glitchedhttps.git`

### How to use

Just add glitchedhttps as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

`git submodule add https://github.com/GlitchedPolygons/glitchedhttps.git lib/`
`git submodule update --init --recursive`

If you use CMake you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE glitchedhttps)`
