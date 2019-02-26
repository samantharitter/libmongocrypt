/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bson/bson.h>

#include "mongocrypt-schema-cache-private.h"

_mongocrypt_schema_cache_t *
_mongocrypt_schema_cache_new (void)
{
   _mongocrypt_schema_cache_t *cache;

   cache = (_mongocrypt_schema_cache_t *) bson_malloc0 (sizeof *cache);

   return cache;
}


mongocrypt_binary_t *
_mongocrypt_schema_cache_lookup_ns (_mongocrypt_schema_cache_t *cache,
				    const char *ns)
{
   /* TODO */
   return NULL;
}

void
_mongocrypt_schema_cache_add_ns (_mongocrypt_schema_cache_t *cache,
				 const char *ns,
				 mongocrypt_binary_t *schema)
{
   /* TODO */
   return;
}

void
_mongocrypt_schema_cache_destroy (_mongocrypt_schema_cache_t *cache)
{
   if (cache) {
      bson_free (cache);
   }
}
