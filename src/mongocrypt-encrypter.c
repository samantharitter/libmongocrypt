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

#include "mongocrypt.h"
#include "mongocrypt-encrypter-private.h"
#include "mongocrypt-schema-cache-private.h"


mongocrypt_encrypter_t *
mongocrypt_encrypter_new (mongocrypt_t *crypt,
			  const mongocrypt_opts_t *opts,
			  const mongocrypt_binary_t *schema,
			  const mongocrypt_binary_t *cmd,
			  mongocrypt_status_t *status)
{
   mongocrypt_encrypter_t *request;

   request = (mongocrypt_encrypter_t *) bson_malloc0 (sizeof *request);

   request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_NS;
   request->crypt = crypt;

   return request;
}

mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_ns (mongocrypt_encrypter_t *request,
			     const char *ns)
{
   _mongocrypt_schema_cache_t *cache;
   mongocrypt_binary_t *schema;

   if (request->state != MONGOCRYPT_ENCRYPTER_STATE_NEED_NS) {
      return request->state;
   }

   request->ns = ns;

   cache = _mongocrypt_schema_cache (request->crypt);
   schema = _mongocrypt_schema_cache_lookup_ns (cache, ns);

   if (schema) {
      request->schema = schema;
      // We might not need schema checked here, how to know?
      request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA_CHECKED;
   } else {
      request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA;
   }

   return request->state;
}

mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_schema(mongocrypt_encrypter_t *request,
				mongocrypt_binary_t *schema)
{
   _mongocrypt_schema_cache_t *cache;

   BSON_ASSERT (request);
   if (!(schema && request->state == MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA)) {
      return request->state;
   }

   cache = _mongocrypt_schema_cache (request->crypt);
   _mongocrypt_schema_cache_add_ns (cache, request->ns, schema);

   request->schema = schema;
   request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA_CHECKED;

   return request->state;
}

mongocrypt_encrypter_state_t
mongocrypt_encrypter_validate_schema (mongocrypt_encrypter_t *request,
				      mongocrypt_binary_t *result)
{
   if (!(result && request->state == MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA_CHECKED)) {
      return request->state;
   }

   // TODO, not sure what this step actually means.
   // also, should we be adding to the cache here, after validation,
   // instead of in add_schema ?
   request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_MARKINGS;
   return request->state;
}


mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_markings (mongocrypt_encrypter_t *request,
				   mongocrypt_binary_t *marked_cmd)
{
   BSON_ASSERT (request);
   if (!(marked_cmd && request->state == MONGOCRYPT_ENCRYPTER_STATE_NEED_MARKINGS)) {
      return request->state;
   }

   // TODO: check if we actually need keys.
   request->state = MONGOCRYPT_ENCRYPTER_STATE_NEED_KEYS;
   request->marked_cmd = marked_cmd;

   return request->state;
}


const mongocrypt_key_query_t *
mongocrypt_encrypter_next_key_query (mongocrypt_encrypter_t *request,
				     const mongocrypt_opts_t *opts)
{
   BSON_ASSERT (request);

   /* TODO */

   return NULL;
}


mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_keys (mongocrypt_encrypter_t *request,
			       const mongocrypt_opts_t *opts,
			       const mongocrypt_binary_t *responses,
			       uint32_t num_responses,
			       mongocrypt_status_t *status)
{
   BSON_ASSERT (request);

   if (request->state != MONGOCRYPT_ENCRYPTER_STATE_NEED_KEYS) {
      return request->state;
   }

   /* TODO */
   request->state = MONGOCRYPT_ENCRYPTER_STATE_FINISHED;

   return request->state;
}


mongocrypt_encrypter_state_t
mongocrypt_encrypter_state (mongocrypt_encrypter_t *request)
{
   BSON_ASSERT (request);

   return request->state;
}


void
mongocrypt_encrypter_destroy (mongocrypt_encrypter_t *request)
{
   if (!request) {
      return;
   }

   mongocrypt_binary_destroy (request->schema);
   mongocrypt_binary_destroy (request->marked_cmd);
   bson_free ((char *)request->ns);

   bson_free (request);
}
