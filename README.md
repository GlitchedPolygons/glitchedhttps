[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1769711fb52041daa272e209aaddb0f4)](https://www.codacy.com/manual/GlitchedPolygons/glitchedhttps?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/glitchedhttps&amp;utm_campaign=Badge_Grade)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/glitchedhttps/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/glitchedhttps)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/glitchedhttps/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/glitchedhttps/tree/master)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/glitchedhttps/)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/glitchedhttps/blob/master/LICENSE)

# Glitched HTTPS
### Simple, lightweight and straight-forward way of doing HTTP(S) requests in C with the help of [ARM's open-source MbedTLS library](https://github.com/ARMmbed/mbedtls).

> ᐳᐳ  Check out the API docs [here on github.io](https://glitchedpolygons.github.io/glitchedhttps/files.html)

### How to clone

`git clone https://github.com/GlitchedPolygons/glitchedhttps.git`

### How to use

Just add glitchedhttps as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/glitchedhttps.git lib/glitchedhttps
git submodule update --init --recursive
```

If you use CMake you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE glitchedhttps)` inside your **CMakeLists.txt** file.

### Simple GET Request

Here's how you can get started. Quick and easy setup:

```C
#include <glitchedhttps.h>

int main() 
{
    /* 
     * Please note that you MUST include the scheme, 
     * ergo the URL must start with `http://` or `https://` 
     * (it won't default to one of the two!). 
     */
     
    struct glitchedhttps_request request;
    glitchedhttps_request_init(&request);

    request.url = "https://example.com/";
    request.method = GLITCHEDHTTPS_GET;

    glitchedhttps_response* response = NULL;

    int result = glitchedhttps_submit(&request, &response);

    if (result == GLITCHEDHTTPS_SUCCESS)
    {
        printf("\n SUCCESS! \n");
    }

    printf("\n Response from %s: \n\n %s \n", request.url, response != NULL ? response->content : "(NULL)");
    
    glitchedhttps_response_free(response);
    
    return 0;
}
```

---

### POST Request example

Sending POST requests with parameters, request body, custom HTTP headers and everything is possible!

Also: NEVER forget to `glitchedhttps_response_free(response);` to prevent memory leaks!

Check out the other examples inside the [`examples/`](https://github.com/GlitchedPolygons/glitchedhttps/tree/master/examples) folder too!

```C
#include <time.h>
#include <glitchedhttps.h>

int main()
{
    struct glitchedhttps_request request;
    glitchedhttps_request_init(&request);

    request.url = "https://postman-echo.com/post";
    request.method = GLITCHEDHTTPS_POST;
    request.content_type = "application/json";
    request.content = "{\"foo\" : \"bar\", \"test\" : \"value\"}";
    request.content_length = strlen(request.content);

    struct glitchedhttps_response* response = NULL;

    clock_t begin = clock();
    
    int result = glitchedhttps_submit(&request, &response);
    
    clock_t end = clock();

    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000;

    const bool success =
            result == GLITCHEDHTTPS_SUCCESS
            && response != NULL
            && response->status_code >= 200
            && response->status_code < 300;

    if (success)
    {
        printf("\nConnection test SUCCESSFUL! Status Code: %d\n", response->status_code);
    }

    printf("\nResponse (%d ms) from %s: \n\n%s\n", (int)time_spent, request.url, response != NULL ? response->content : "(NULL)");

    glitchedhttps_response_free(response);

    return 0;
}
```
