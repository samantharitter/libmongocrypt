/*
 * Copyright 2019-present MongoDB, Inc.
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

#include "mongocrypt-private.h"
#include "mongocrypt-ciphertext-private.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-ctx-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-marking-private.h"
#include "mongocrypt-traverse-util-private.h"

/* Construct the list collections command to send. */
static bool
_mongo_op_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *cmd;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   cmd = BCON_NEW ("name", BCON_UTF8 (ectx->coll_name));
   CRYPT_TRACEF (&ectx->parent.crypt->log, "constructed: %s\n", tmp_json (cmd));
   _mongocrypt_buffer_steal_from_bson (&ectx->list_collections_filter, cmd);
   out->data = ectx->list_collections_filter.data;
   out->len = ectx->list_collections_filter.len;
   return true;
}

static bool
_set_schema_from_collinfo (mongocrypt_ctx_t *ctx, bson_t *collinfo)
{
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   /* Parse out the schema. */
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* Disallow views. */
   if (bson_iter_init_find (&iter, collinfo, "type") &&
       BSON_ITER_HOLDS_UTF8 (&iter) &&
       0 == strcmp ("view", bson_iter_utf8 (&iter, NULL))) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "cannot auto encrypt a view");
   }

   if (!bson_iter_init (&iter, collinfo)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }

   if (bson_iter_find_descendant (
          &iter, "options.validator.$jsonSchema", &iter)) {
      if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed JSONSchema");
      }
   }

   /* TODO CDRIVER-3096 check for validator siblings. */
   return true;
}

static bool
_mongo_feed_collinfo (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   bson_t as_bson;

   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!bson_init_static (&as_bson, in->data, in->len)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "BSON malformed");
   }

   /* Cache the received collinfo. */
   if (!_mongocrypt_cache_add_copy (
          &ctx->crypt->cache_collinfo, ectx->ns, &as_bson, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (!_set_schema_from_collinfo (ctx, &as_bson)) {
      return false;
   }

   return true;
}


static bool
_mongo_done_collinfo (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ectx->parent.state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   return true;
}


static bool
_mongo_op_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t cmd_bson, schema_bson, mongocryptd_cmd_bson;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (_mongocrypt_buffer_empty (&ectx->mongocryptd_cmd)) {
      /* first, get the original command. */
      if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &cmd_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON cmd");
      }

      if (_mongocrypt_buffer_empty (&ectx->schema)) {
         bson_init (&schema_bson);
      } else if (!_mongocrypt_buffer_to_bson (&ectx->schema, &schema_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "invalid BSON schema");
      }

      bson_copy_to (&cmd_bson, &mongocryptd_cmd_bson);
      BSON_APPEND_DOCUMENT (&mongocryptd_cmd_bson, "jsonSchema", &schema_bson);

      /* if a local schema was not set, set isRemoteSchema=true */
      BSON_APPEND_BOOL (
         &mongocryptd_cmd_bson, "isRemoteSchema", !ectx->used_local_schema);
      _mongocrypt_buffer_steal_from_bson (&ectx->mongocryptd_cmd,
                                          &mongocryptd_cmd_bson);

      bson_destroy (&cmd_bson);
      bson_destroy (&schema_bson);
   }
   out->data = ectx->mongocryptd_cmd.data;
   out->len = ectx->mongocryptd_cmd.len;
   return true;
}


static bool
_collect_key_from_marking (void *ctx,
                           _mongocrypt_buffer_t *in,
                           mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking;
   _mongocrypt_key_broker_t *kb;
   bool res;

   kb = (_mongocrypt_key_broker_t *) ctx;

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   /* TODO: check if the key cache has the key. */
   if (marking.has_alt_name) {
      res = _mongocrypt_key_broker_add_name (kb, &marking.key_alt_name);
   } else {
      res = _mongocrypt_key_broker_add_id (kb, &marking.key_id);
   }

   if (!res) {
      _mongocrypt_key_broker_status (kb, status);
      return false;
   }

   _mongocrypt_marking_cleanup (&marking);

   return true;
}


static bool
_mongo_feed_markings (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *in)
{
   /* Find keys. */
   bson_t as_bson;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   if (!_mongocrypt_binary_to_bson (in, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed BSON");
   }

   if (bson_iter_init_find (&iter, &as_bson, "schemaRequiresEncryption") &&
       !bson_iter_as_bool (&iter)) {
      /* TODO: update cache: this schema does not require encryption. */

      /* If using a local schema, warn if there are no encrypted fields. */
      if (!ectx->used_local_schema) {
         _mongocrypt_log (
            &ctx->crypt->log,
            MONGOCRYPT_LOG_LEVEL_WARNING,
            "local schema used but does not have encryption specifiers");
      }
      return true;
   }

   if (bson_iter_init_find (&iter, &as_bson, "hasEncryptedPlaceholders") &&
       !bson_iter_as_bool (&iter)) {
      return true;
   }

   if (!bson_iter_init_find (&iter, &as_bson, "result")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed marking, no 'result'");
   }

   if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->marked_cmd, &iter)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "malformed marking, 'result' must be a document");
   }

   bson_iter_recurse (&iter, &iter);
   if (!_mongocrypt_traverse_binary_in_bson (_collect_key_from_marking,
                                             (void *) &ctx->kb,
                                             TRAVERSE_MATCH_MARKING,
                                             &iter,
                                             ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   return true;
}


static bool
_mongo_done_markings (mongocrypt_ctx_t *ctx)
{
   return _mongocrypt_ctx_state_from_key_broker (ctx);
}


static bool
_marking_to_bson_value (void *ctx,
                        _mongocrypt_marking_t *marking,
                        bson_value_t *out,
                        mongocrypt_status_t *status)
{
   _mongocrypt_ciphertext_t ciphertext;
   _mongocrypt_buffer_t serialized_ciphertext = {0};
   bool ret = false;

   BSON_ASSERT (out);

   _mongocrypt_ciphertext_init (&ciphertext);

   if (!_mongocrypt_marking_to_ciphertext (ctx, marking, &ciphertext, status)) {
      goto fail;
   }

   if (!_mongocrypt_serialize_ciphertext (&ciphertext,
                                          &serialized_ciphertext)) {
      CLIENT_ERR ("malformed ciphertext");
      goto fail;
   };

   /* ownership of serialized_ciphertext is transferred to caller. */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.data = serialized_ciphertext.data;
   out->value.v_binary.data_len = serialized_ciphertext.len;
   out->value.v_binary.subtype = 6;

   ret = true;

fail:
   _mongocrypt_ciphertext_cleanup (&ciphertext);
   return ret;
}


static bool
_replace_marking_with_ciphertext (void *ctx,
                                  _mongocrypt_buffer_t *in,
                                  bson_value_t *out,
                                  mongocrypt_status_t *status)
{
   _mongocrypt_marking_t marking = {0};

   BSON_ASSERT (in);

   if (!_mongocrypt_marking_parse_unowned (in, &marking, status)) {
      return false;
   }

   return _marking_to_bson_value (ctx, &marking, out, status);
}

static bool
_finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out)
{
   bson_t as_bson, converted;
   bson_iter_t iter;
   _mongocrypt_ctx_encrypt_t *ectx;
   bool res = true;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (!ectx->explicit) {
      if (ctx->nothing_to_do) {
         _mongocrypt_buffer_to_binary (&ectx->original_cmd, out);
         ctx->state = MONGOCRYPT_CTX_DONE;
         return true;
      }
      if (!_mongocrypt_buffer_to_bson (&ectx->marked_cmd, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

      bson_iter_init (&iter, &as_bson);
      bson_init (&converted);
      if (!_mongocrypt_transform_binary_in_bson (
             _replace_marking_with_ciphertext,
             &ctx->kb,
             TRAVERSE_MATCH_MARKING,
             &iter,
             &converted,
             ctx->status)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      /* For explicit encryption, we have no marking, but we can fake one */
      _mongocrypt_marking_t marking;
      bson_value_t value;

      _mongocrypt_marking_init (&marking);

      if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed bson");
      }

      if (!bson_iter_init_find (&iter, &as_bson, "v")) {
         return _mongocrypt_ctx_fail_w_msg (ctx,
                                            "invalid msg, must contain 'v'");
      }


      memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));
      marking.algorithm = ctx->opts.algorithm;
      _mongocrypt_buffer_set_to (&ctx->opts.key_id, &marking.key_id);

      bson_init (&converted);
      res = _marking_to_bson_value (&ctx->kb, &marking, &value, ctx->status);
      if (res) {
         bson_append_value (&converted, MONGOCRYPT_STR_AND_LEN ("v"), &value);
      }

      bson_value_destroy (&value);
      _mongocrypt_marking_cleanup (&marking);

      if (!res) {
         return false;
      }
   }

   _mongocrypt_buffer_steal_from_bson (&ectx->encrypted_cmd, &converted);
   _mongocrypt_buffer_to_binary (&ectx->encrypted_cmd, out);
   ctx->state = MONGOCRYPT_CTX_DONE;

   return true;
}


static void
_cleanup (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   bson_free (ectx->ns);
   bson_free (ectx->db_name);
   bson_free (ectx->coll_name);
   _mongocrypt_buffer_cleanup (&ectx->list_collections_filter);
   _mongocrypt_buffer_cleanup (&ectx->schema);
   _mongocrypt_buffer_cleanup (&ectx->original_cmd);
   _mongocrypt_buffer_cleanup (&ectx->mongocryptd_cmd);
   _mongocrypt_buffer_cleanup (&ectx->marked_cmd);
   _mongocrypt_buffer_cleanup (&ectx->encrypted_cmd);
}


static bool
_try_schema_from_schema_map (mongocrypt_ctx_t *ctx)
{
   mongocrypt_t *crypt;
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t schema_map;
   bson_iter_t iter;

   crypt = ctx->crypt;
   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   if (_mongocrypt_buffer_empty (&crypt->opts.schema_map)) {
      /* No schema map set. */
      return true;
   }

   if (!_mongocrypt_buffer_to_bson (&crypt->opts.schema_map, &schema_map)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "malformed schema map");
   }

   if (bson_iter_init_find (&iter, &schema_map, ectx->ns)) {
      if (!_mongocrypt_buffer_copy_from_document_iter (&ectx->schema, &iter)) {
         return _mongocrypt_ctx_fail_w_msg (ctx, "malformed schema map");
      }
      ectx->used_local_schema = true;
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   }

   /* No schema found in map. */
   return true;
}


static bool
_try_schema_from_cache (mongocrypt_ctx_t *ctx)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t *collinfo = NULL;

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;

   /* Otherwise, we need a remote schema. Check if we have a response to
      * listCollections cached. */
   if (!_mongocrypt_cache_get (&ctx->crypt->cache_collinfo,
                               ectx->ns /* null terminated */,
                               (void **) &collinfo)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "failed to retrieve from cache");
   }

   if (collinfo) {
      if (!_set_schema_from_collinfo (ctx, collinfo)) {
         return _mongocrypt_ctx_fail (ctx);
      }
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_MARKINGS;
   } else {
      /* we need to get it. */
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   }

   bson_destroy (collinfo);
   return true;
}


bool
mongocrypt_ctx_explicit_encrypt_init (mongocrypt_ctx_t *ctx,
                                      mongocrypt_binary_t *msg)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   bson_t as_bson;
   bson_iter_t iter;

   _mongocrypt_ctx_opts_spec_t opts_spec = {0};

   opts_spec.key_descriptor = OPT_REQUIRED;
   opts_spec.algorithm = OPT_REQUIRED;

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->explicit = true;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;

   if (!msg || !msg->data) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "msg required for explicit encryption");
   }

   if (ctx->opts.key_alt_name) {
      if (!_mongocrypt_key_broker_add_name (&ctx->kb, ctx->opts.key_alt_name)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   } else {
      if (!_mongocrypt_key_broker_add_id (&ctx->kb, &ctx->opts.key_id)) {
         return _mongocrypt_ctx_fail (ctx);
      }
   }

   _mongocrypt_buffer_init (&ectx->original_cmd);

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, msg);
   if (!_mongocrypt_buffer_to_bson (&ectx->original_cmd, &as_bson)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "msg must be bson");
   }

   if (!bson_iter_init_find (&iter, &as_bson, "v")) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid msg, must contain 'v'");
   }

   /* Check for prohibited types. */
   if (BSON_ITER_HOLDS_NULL (&iter) || BSON_ITER_HOLDS_MINKEY (&iter) ||
       BSON_ITER_HOLDS_MAXKEY (&iter) || BSON_ITER_HOLDS_UNDEFINED (&iter)) {
      return _mongocrypt_ctx_fail_w_msg (ctx,
                                         "BSON type invalid for encryption");
   }
   /* Check for prohibited deterministic types */
   if (ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC) {
      if (BSON_ITER_HOLDS_DOCUMENT (&iter) || BSON_ITER_HOLDS_ARRAY (&iter) ||
          BSON_ITER_HOLDS_CODEWSCOPE (&iter) ||
          BSON_ITER_HOLDS_DOUBLE (&iter) ||
          BSON_ITER_HOLDS_DECIMAL128 (&iter) || BSON_ITER_HOLDS_BOOL (&iter)) {
         return _mongocrypt_ctx_fail_w_msg (
            ctx, "BSON type invalid for deterministic encryption");
      }
   }


   return _mongocrypt_ctx_state_from_key_broker (ctx);
}

static bool
_check_cmd_for_auto_encrypt (mongocrypt_binary_t *cmd,
                             bool *bypass,
                             char **collname,
                             mongocrypt_status_t *status)
{
   bson_t as_bson;
   bson_iter_t iter, ns_iter;
   const char *cmd_name;
   bool eligible = false;

   *bypass = false;

   if (!_mongocrypt_binary_to_bson (cmd, &as_bson) ||
       !bson_iter_init (&iter, &as_bson)) {
      CLIENT_ERR ("invalid BSON");
      return false;
   }

   /* The command name is the first key. */
   if (!bson_iter_next (&iter)) {
      CLIENT_ERR ("invalid empty BSON");
      return false;
   }

   cmd_name = bson_iter_key (&iter);

   /* get the collection name (or NULL if database/client command). */
   if (0 == strcmp (cmd_name, "explain")) {
      if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
         CLIENT_ERR ("explain value is not a document");
         return false;
      }
      if (!bson_iter_recurse (&iter, &ns_iter)) {
         CLIENT_ERR ("malformed BSON for encrypt command");
         return false;
      }
      if (!bson_iter_next (&ns_iter)) {
         CLIENT_ERR ("invalid empty BSON");
         return false;
      }
   } else {
      memcpy (&ns_iter, &iter, sizeof (iter));
   }

   if (BSON_ITER_HOLDS_UTF8 (&ns_iter)) {
      *collname = bson_strdup (bson_iter_utf8 (&ns_iter, NULL));
   } else {
      *collname = NULL;
   }

   /* check if command is eligible for auto encryption, bypassed, or ineligible.
    */
   if (0 == strcmp (cmd_name, "aggregate")) {
      /* collection level aggregate ok, database/client is not. */
      eligible = true;
   } else if (0 == strcmp (cmd_name, "count")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "distinct")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "delete")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "find")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "findAndModify")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "getMore")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "insert")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "update")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "authenticate")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "getnonce")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "logout")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "isMaster")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "abortTransaction")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "commitTransaction")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "endSessions")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "startSession")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "create")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "createIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "drop")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "dropDatabase")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "dropIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "killCursors")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listCollections")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listDatabases")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "listIndexes")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "renameCollection")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "explain")) {
      eligible = true;
   } else if (0 == strcmp (cmd_name, "ping")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "saslStart")) {
      *bypass = true;
   } else if (0 == strcmp (cmd_name, "saslContinue")) {
      *bypass = true;
   }

   /* database/client commands are ineligible. */
   if (eligible) {
      if (!*collname) {
         CLIENT_ERR (
            "non-collection command not supported for auto encryption: %s",
            cmd_name);
         return false;
      }
      if (0 == strlen (*collname)) {
         CLIENT_ERR ("empty collection name on command: %s", cmd_name);
         return false;
      }
   }

   if (eligible || *bypass) {
      return true;
   }

   CLIENT_ERR ("command not supported for auto encryption: %s", cmd_name);
   return false;
}

bool
mongocrypt_ctx_encrypt_init (mongocrypt_ctx_t *ctx,
                             const char *db,
                             int32_t db_len,
                             mongocrypt_binary_t *cmd)
{
   _mongocrypt_ctx_encrypt_t *ectx;
   _mongocrypt_ctx_opts_spec_t opts_spec = {0};
   bool bypass;

   opts_spec.schema = OPT_OPTIONAL;
   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return false;
   }

   ectx = (_mongocrypt_ctx_encrypt_t *) ctx;
   ctx->type = _MONGOCRYPT_TYPE_ENCRYPT;
   ectx->explicit = false;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
   ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_op_markings = _mongo_op_markings;
   ctx->vtable.mongo_feed_markings = _mongo_feed_markings;
   ctx->vtable.mongo_done_markings = _mongo_done_markings;
   ctx->vtable.finalize = _finalize;
   ctx->vtable.cleanup = _cleanup;
   ctx->vtable.mongo_op_collinfo = _mongo_op_collinfo;
   ctx->vtable.mongo_feed_collinfo = _mongo_feed_collinfo;
   ctx->vtable.mongo_done_collinfo = _mongo_done_collinfo;


   if (!cmd || !cmd->data) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid command");
   }

   _mongocrypt_buffer_copy_from_binary (&ectx->original_cmd, cmd);

   if (!_check_cmd_for_auto_encrypt (
          cmd, &bypass, &ectx->coll_name, ctx->status)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   if (bypass) {
      ctx->nothing_to_do = true;
      ctx->state = MONGOCRYPT_CTX_READY;
      return true;
   }

   /* if _check_cmd_for_auto_encrypt did not bypass or error, a collection name
    * must have been set. */
   if (!ectx->coll_name) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx,
         "unexpected error: did not bypass or error but no collection name");
   }

   if (!_mongocrypt_validate_and_copy_string (db, db_len, &ectx->db_name) ||
       0 == strlen (ectx->db_name)) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "invalid db");
   }

   ectx->ns = bson_strdup_printf ("%s.%s", ectx->db_name, ectx->coll_name);

   if (ctx->opts.masterkey_aws_region || ctx->opts.masterkey_aws_cmk) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "aws masterkey options must not be set");
   }

   if (!_mongocrypt_buffer_empty (&ctx->opts.key_id)) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "key_id must not be set for auto encryption");
   }

   if (ctx->opts.algorithm != MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE) {
      return _mongocrypt_ctx_fail_w_msg (
         ctx, "algorithm must not be set for auto encryption");
   }

   /* Check if we have a local schema from schema_map */
   if (!_try_schema_from_schema_map (ctx)) {
      return false;
   }

   /* If we didn't have a local schema, try the cache. */
   if (_mongocrypt_buffer_empty (&ectx->schema)) {
      if (!_try_schema_from_cache (ctx)) {
         return false;
      }
   }

   /* Otherwise, we need the the driver to fetch the schema. */
   if (_mongocrypt_buffer_empty (&ectx->schema)) {
      ctx->state = MONGOCRYPT_CTX_NEED_MONGO_COLLINFO;
   }
   return true;
}
