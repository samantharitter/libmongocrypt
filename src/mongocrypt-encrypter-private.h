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

#ifndef MONGOCRYPT_ENCRYPTER_PRIVATE_H
#define MONGOCRYPT_ENCRYPTER_PRIVATE_H

#include "mongocrypt-private.h"
#include "mongocrypt-encrypter.h"

struct _mongocrypt_encrypter_t {
   mongocrypt_t *crypt;
   mongocrypt_encrypter_state_t state;
   mongocrypt_binary_t *schema;
   mongocrypt_binary_t *marked_cmd;
   const char *ns;
};


#endif /* MONGOCRYPT_ENCRYPTER_PRIVATE_H */
