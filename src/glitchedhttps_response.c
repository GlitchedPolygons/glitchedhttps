/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_response.h"

void glitchedhttps_response_free(struct glitchedhttps_response* response)
{
    if (response == NULL)
    {
        return;
    }

    free(response->raw);
    response->raw = NULL;

    free(response->server);
    response->server = NULL;

    free(response->date);
    response->date = NULL;

    free(response->content);
    response->content = NULL;

    free(response->content_type);
    response->content_type = NULL;

    free(response->content_encoding);
    response->content_encoding = NULL;

    if (response->headers_count > 0)
    {
        for (size_t i = 0; i < response->headers_count; ++i)
        {
            struct glitchedhttps_header* h = &(response->headers[i]);

            if (h == NULL)
                continue;

            free(h->type);
            free(h->value);
        }
        free(response->headers);
    }

    free(response);
}

#ifdef __cplusplus
} // extern "C"
#endif
