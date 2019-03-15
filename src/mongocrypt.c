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

#include <kms_message/kms_message.h>
#include <bson/bson.h>

#include "mongocrypt-binary.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-schema-cache-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt-log-private.h"

static void
_print_bin (_mongocrypt_buffer_t *buf)
{
   uint32_t i;

   for (i = 0; i < buf->len; i++) {
      printf ("%02x", buf->data[i]);
   }
   printf ("\n");
}

const char *
mongocrypt_version (void)
{
   return MONGOCRYPT_VERSION;
}

void
_mongocrypt_set_error (mongocrypt_status_t *status,
                       uint32_t type,
                       uint32_t code,
                       const char *format,
                       ...)
{
   size_t max_msg_len;
   int len;
   va_list args;

   if (status) {
      max_msg_len = sizeof status->message;
      status->type = type;
      status->code = code;

      va_start (args, format);
      len = bson_vsnprintf (status->message, max_msg_len - 1, format, args);
      va_end (args);

      status->message[len] = '\0';
   }
}


void
_bson_error_to_mongocrypt_error (const bson_error_t *bson_error,
                                 uint32_t type,
                                 uint32_t code,
                                 mongocrypt_status_t *status)
{
   _mongocrypt_set_error (status, type, code, "%s", bson_error->message);
}


const char *
tmp_json (const bson_t *bson)
{
   static char storage[1024];
   char *json;

   memset (storage, 0, 1024);
   json = bson_as_json (bson, NULL);
   bson_snprintf (storage, sizeof (storage), "%s", json);
   bson_free (json);
   return (const char *) storage;
}


const char *
tmp_buf (const _mongocrypt_buffer_t *buf)
{
   static char storage[1024];
   int i, n;

   memset (storage, 0, 1024);
   /* capped at two characters per byte, minus 1 for trailing \0 */
   n = sizeof (storage) / 2 - 1;
   if (buf->len < n) {
      n = buf->len;
   }

   for (i = 0; i < n; i++) {
      bson_snprintf (storage + (i * 2), 3, "%02x", buf->data[i]);
   }

   return (const char *) storage;
}


MONGOCRYPT_ONCE_FUNC (_mongocrypt_do_init)
{
   kms_message_init ();
}


mongocrypt_t *
mongocrypt_new (const mongocrypt_opts_t *opts, mongocrypt_status_t *status)
{
   mongocrypt_t *crypt = NULL;
   bool success = false;

   _mongocrypt_do_init ();
   crypt = bson_malloc0 (sizeof (mongocrypt_t));
   crypt->opts = mongocrypt_opts_copy (opts);
   mongocrypt_mutex_init (&crypt->mutex);
   _mongocrypt_log_init (&crypt->log, opts);
   crypt->schema_cache = _mongocrypt_schema_cache_new ();
   success = true;

fail:
   if (!success) {
      mongocrypt_destroy (crypt);
      crypt = NULL;
   }
   return crypt;
}


void
mongocrypt_destroy (mongocrypt_t *crypt)
{
   if (!crypt) {
      return;
   }
   mongocrypt_opts_destroy (crypt->opts);
   _mongocrypt_schema_cache_destroy (crypt->schema_cache);
   _mongocrypt_key_cache_destroy (crypt->key_cache);
   mongocrypt_mutex_destroy (&crypt->mutex);
   _mongocrypt_log_cleanup (&crypt->log);
   bson_free (crypt);
}
