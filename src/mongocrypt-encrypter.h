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

#ifndef MONGOCRYPT_ENCRYPTER_H
#define MONGOCRYPT_ENCRYPTER_H


#include "mongocrypt-binary.h"
#include "mongocrypt-key-query.h"
#include "mongocrypt-opts.h"
#include "mongocrypt-status.h"

typedef struct _mongocrypt_encrypter_t mongocrypt_encrypter_t;

typedef enum {
   MONGOCRYPT_ENCRYPTER_STATE_NEED_NS,
   MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA,
   MONGOCRYPT_ENCRYPTER_STATE_NEED_SCHEMA_CHECKED,
   MONGOCRYPT_ENCRYPTER_STATE_NEED_MARKINGS,
   MONGOCRYPT_ENCRYPTER_STATE_NEED_KEYS,
   MONGOCRYPT_ENCRYPTER_NO_ENCRYPTION_NEEDED,
   MONGOCRYPT_ENCRYPTER_STATE_FINISHED,
   MONGOCRYPT_ENCRYPTER_STATE_ERROR
} mongocrypt_encrypter_state_t;


mongocrypt_encrypter_t *
mongocrypt_encrypter_new (mongocrypt_t *crypt,
			  const mongocrypt_opts_t *opts,
			  const mongocrypt_binary_t *schema,
			  const mongocrypt_binary_t *cmd,
			  mongocrypt_status_t *status);


mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_ns (mongocrypt_encrypter_t *request,
			     const char *ns);

mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_schema(mongocrypt_encrypter_t *request,
				mongocrypt_binary_t *schema);


mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_markings(mongocrypt_encrypter_t *request,
				  mongocrypt_binary_t *marked_cmd);


const mongocrypt_key_query_t *
mongocrypt_encrypter_next_key_query (mongocrypt_encrypter_t *request,
				     const mongocrypt_opts_t *opts);


mongocrypt_encrypter_state_t
mongocrypt_encrypter_add_keys (mongocrypt_encrypter_t *request,
			       const mongocrypt_opts_t *opts,
			       const mongocrypt_binary_t *responses,
			       uint32_t num_responses,
			       mongocrypt_status_t *status);


mongocrypt_encrypter_state_t
mongocrypt_encrypter_state (mongocrypt_encrypter_t *request);

void
mongocrypt_encrypter_destroy (mongocrypt_encrypter_t *request);



#endif /* MONGOCRYPT_ENCRYPTER_H */
