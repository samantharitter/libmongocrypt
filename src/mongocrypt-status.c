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

#include "mongocrypt-status-private.h"

mongocrypt_status_t *
mongocrypt_status_new (void)
{
   return bson_malloc0 (sizeof (mongocrypt_status_t));
}


const char *
mongocrypt_status_message (mongocrypt_status_t *status)
{
   return status->message;
}


uint32_t
mongocrypt_status_code (mongocrypt_status_t *status)
{
   return status->code;
}


mongocrypt_error_type_t
mongocrypt_status_error_type (mongocrypt_status_t *status)
{
   return status->type;
}


bool
mongocrypt_status_ok (mongocrypt_status_t *status)
{
   return (status->type == MONGOCRYPT_ERROR_TYPE_NONE);
}


void
mongocrypt_status_reset (mongocrypt_status_t *status)
{
   if (!status) {
      return;
   }

   status->type = MONGOCRYPT_ERROR_TYPE_NONE;
   status->code = 0;

   bson_free (status->ctx);
   status->ctx = NULL;

   memset (status->message, 0, 1024);
}


void
mongocrypt_status_destroy (mongocrypt_status_t *status)
{
   if (!status) {
      return;
   }
   bson_free (status->ctx);
   bson_free (status);
}
