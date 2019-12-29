
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

If you use CMake you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE glitchedhttps)` inside your **CMakeLists.txt** file.

### Simple GET Request

Here's how you can get started. Quick and easy setup:

```C
#include <glitchedhttps.h>

int main() 
{
    glitchedhttps_request request = 
    {
        .url = "https://example.com/",
        .method = GLITCHEDHTTPS_GET,
        .buffer_size = 4096,
        .ssl_verification_optional = false,
    };

    glitchedhttps_response* response = NULL;

    int result = glitchedhttps_submit(&request, &response);

    if (result == GLITCHEDHTTPS_SUCCESS)
    {
        printf("\n SUCCESS! \n");
    }

    printf("\n Response from %s: \n\n %s \n", request.url, response != NULL ? response->content : "(NULL)");
    
    glitchedhttps_response_free(response);
}
```

---

### POST Request example

Sending POST requests with parameters, request body, custom HTTP headers and everything is possible!

Also: NEVER forget to `glitchedhttps_response_free(response);` to prevent memory leaks!

Check out the other examples inside the [`examples/`](https://github.com/GlitchedPolygons/glitchedhttps/tree/master/examples) folder too!

```C
#include <glitchedhttps.h>

int main()
{
    char* url = "https://postman-echo.com/post";
    char* body = "{ \"foo\" : \"bar\", \"test\" : \"value\" }";
    
    glitchedhttps_header additional_headers[] = 
    {
        { "Another-Foo", "anotherBar" },
        { "Additional-Headers-Are-Cool", "SGVsbG8gV29ybGQh" },
        { "Yet-Another-Header", "You can add as many of these as you want" }
    };
    
    glitchedhttps_request request = 
    {
        .url = url,
        .method = GLITCHEDHTTPS_POST,
        .buffer_size = 1024,
        .ssl_verification_optional = false,
        .content_type = "application/json",
        .content_length = strlen(body),
        .content = body,
        .additional_headers = additional_headers,
        .additional_headers_count = sizeof(additional_headers) / sizeof(glitchedhttps_header)
    };

    glitchedhttps_response* response = NULL;

    int result = glitchedhttps_submit(&request, &response);

    const bool success =
        result == GLITCHEDHTTPS_SUCCESS
        && response != NULL
        && response->status_code >= 200
        && response->status_code < 300;

    if (success)
    {
        printf("\n Connection test SUCCESSFUL! Status Code: %d \n", response->status_code);
    }

    printf("\n Response from %s: \n\n %s \n", request.url, response != NULL ? response->content : "(NULL)");

    glitchedhttps_response_free(response);

    return 0;
}
```
