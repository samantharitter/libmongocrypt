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

#ifndef MONGOCRYPT_SCHEMA_CACHE_H
#define MONGOCRYPT_SCHEMA_CACHE_H

#include "mongocrypt-binary.h"

typedef struct {
   /* TODO */
} _mongocrypt_schema_cache_t;

_mongocrypt_schema_cache_t *
_mongocrypt_schema_cache_new (void);


mongocrypt_binary_t *
_mongocrypt_schema_cache_lookup_ns (_mongocrypt_schema_cache_t *cache,
				    const char *ns);

void
_mongocrypt_schema_cache_add_ns (_mongocrypt_schema_cache_t *cache,
				 const char *ns,
				 mongocrypt_binary_t *schema);

void
_mongocrypt_schema_cache_destroy (_mongocrypt_schema_cache_t *cache);


#endif /* MONGOCRYPT_SCHEMA_CACHE_H */
