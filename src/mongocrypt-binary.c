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

#include "mongocrypt-binary.h"

mongocrypt_binary_t *
mongocrypt_binary_new ()
{
   mongocrypt_binary_t *binary;

   binary = (mongocrypt_binary_t *) bson_malloc0 (sizeof *binary);

   return binary;
}

void
mongocrypt_binary_destroy (mongocrypt_binary_t *binary)
{
   bson_free (binary->data);
   bson_free (binary);
}
