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

#include <mongocrypt.h>
#include <mongocrypt-ciphertext-private.h>
#include <mongocrypt-ctx-private.h>
#include <mongocrypt-key-broker-private.h>

#include "test-mongocrypt.h"


static void
_test_explicit_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *string_msg;
   mongocrypt_binary_t *no_v_msg;
   mongocrypt_binary_t *bad_name;
   mongocrypt_binary_t *name;
   mongocrypt_binary_t *msg;
   mongocrypt_binary_t *key_id;
   mongocrypt_binary_t *iv;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   bson_t *bson_msg;
   bson_t *bson_msg_no_v;
   bson_t *bson_name;
   bson_t *bson_bad_name;

   char *random = "AEAD_AES_256_CBC_HMAC_SHA_512-Randomized";
   char *deterministic = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";

   bson_msg = BCON_NEW ("v", "hello");
   msg = mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (bson_msg),
                                          bson_msg->len);

   bson_msg_no_v = BCON_NEW ("a", "hello");
   no_v_msg = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_msg_no_v), bson_msg_no_v->len);

   bson_name = BCON_NEW ("keyAltName", "Rebekah");
   name = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_name), bson_name->len);

   bson_bad_name = BCON_NEW ("noAltName", "Barry");
   bad_name = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_bad_name), bson_bad_name->len);

   string_msg =
      mongocrypt_binary_new_from_data (MONGOCRYPT_DATA_AND_LEN ("hello"));
   key_id = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("2395340598345034"));
   iv = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("77777777777777777"));

   crypt = _mongocrypt_tester_mongocrypt ();

   /* Initting with no options will fail (need key_id). */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with only key_id will not succeed, we also
      need an algorithm. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "algorithm is required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test null msg input. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, NULL),
                 ctx,
                 "msg required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test with string msg input (no bson) */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, string_msg),
                 ctx,
                 "msg must be bson");
   mongocrypt_ctx_destroy (ctx);

   /* Test with input bson that has no "v" field */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, no_v_msg),
                 ctx,
                 "invalid msg, must contain 'v'");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with RANDOM without an iv passes */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
   BSON_ASSERT (_mongocrypt_buffer_empty (&ctx->opts.iv));
   mongocrypt_ctx_destroy (ctx);

   /* Initting with RANDOM with an iv fails */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "iv must not be set for random encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test that bad algorithm input fails */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_setopt_algorithm (ctx, "nonexistent algorithm", -1),
      ctx,
      "unsupported algorithm");
   mongocrypt_ctx_destroy (ctx);

   /* Test that specifying DETERMINISTIC without an iv fails */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_id (ctx, key_id));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "iv is required for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test that specifying DETERMINISTIC with an iv passes */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_id (ctx, key_id));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (!_mongocrypt_buffer_empty (&ctx->opts.iv));
   BSON_ASSERT (memcmp (iv->data, ctx->opts.iv.data, iv->len) == 0);
   mongocrypt_ctx_destroy (ctx);

   /* Test with badly formatted key alt name */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_alt_name (ctx, bad_name));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_FAILS (
      mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx, "must have field");
   mongocrypt_ctx_destroy (ctx);

   /* Test with key alt name */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_alt_name (ctx, name));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (!_mongocrypt_buffer_empty (&ctx->opts.iv));
   BSON_ASSERT (memcmp (iv->data, ctx->opts.iv.data, iv->len) == 0);

   /* After initing, we should be at NEED_KEYS */
   BSON_ASSERT (ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
   BSON_ASSERT (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);

   mongocrypt_binary_destroy (msg);
   mongocrypt_binary_destroy (bad_name);
   mongocrypt_binary_destroy (name);
   mongocrypt_binary_destroy (string_msg);
   mongocrypt_binary_destroy (no_v_msg);
   mongocrypt_binary_destroy (key_id);
   mongocrypt_binary_destroy (iv);
   bson_destroy (bson_bad_name);
   bson_destroy (bson_name);
   bson_destroy (bson_msg);
   bson_destroy (bson_msg_no_v);
}

/* Test individual ctx states. */
static void
_test_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt ();


   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   /* Invalid namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (
                    ctx, MONGOCRYPT_STR_AND_LEN ("invalidnamespace")),
                 ctx,
                 "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* NULL namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (ctx, NULL, 0), ctx, "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Wrong state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx, "wrong state");
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo = _mongocrypt_tester_file (
      tester, "./test/data/collection-info-no-schema.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with NULL schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx, "wrong state");
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_markings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Key alt name. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/example/mongocryptd-reply-key-alt-name.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No placeholders. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-markings.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No encryption in schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-encryption-needed.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Invalid marking. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-invalid.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "no 'v'");
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* NULL markings. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "wrong state");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *key;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   key = _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, key), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (key);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Did not provide all keys. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_done (ctx), ctx, "did not provide all keys");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */
}


static void
_test_encrypt_ready (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted_cmd;
   _mongocrypt_buffer_t ciphertext_buf;
   _mongocrypt_ciphertext_t ciphertext;
   bson_t as_bson;
   bson_iter_t iter;
   bool ret;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   encrypted_cmd = mongocrypt_binary_new ();

   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, encrypted_cmd), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_DONE);

   /* check that the encrypted command has a valid ciphertext. */
   _mongocrypt_binary_to_bson (encrypted_cmd, &as_bson);
   CRYPT_TRACEF (&crypt->log, "encrypted doc: %s", tmp_json (&as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   _mongocrypt_buffer_from_iter (&ciphertext_buf, &iter);
   ret = _mongocrypt_ciphertext_parse_unowned (
      &ciphertext_buf, &ciphertext, status);
   ASSERT_OR_PRINT (ret, status);
   mongocrypt_binary_destroy (encrypted_cmd);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_missing_region (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *key_doc;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   key_doc = _mongocrypt_tester_file (
      tester, "./test/data/key-document-no-region.json");
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_feed (ctx, key_doc), ctx, "no key region");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_binary_destroy (key_doc);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


/* Test that attempting to auto encrypt on a view is disallowed. */
static void
_test_view (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/data/collection-info-view.json");
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, collinfo),
                 ctx,
                 "cannot auto encrypt a view");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_binary_destroy (collinfo);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_local_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *schema, *bin;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   schema = _mongocrypt_tester_file (tester, "./test/data/schema.json");
   ASSERT_OK (mongocrypt_ctx_setopt_schema (ctx, schema), ctx);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   /* Since we supplied a schema, we should jump right to NEED_MONGO_MARKINGS */
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   bin = mongocrypt_binary_new ();
   mongocrypt_ctx_mongo_op (ctx, bin);
   /* We should get back the schema we gave. */
   BSON_ASSERT (0 == memcmp (bin->data, schema->data, schema->len));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);

   mongocrypt_binary_destroy (bin);
   mongocrypt_binary_destroy (schema);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_caches_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;
   bson_t *cached_collinfo;
   mongocrypt_status_t *status;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   status = mongocrypt_status_new ();
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   /* The next crypt has the schema cached. */
   ASSERT_OR_PRINT (_mongocrypt_cache_get (&crypt->cache_collinfo,
                                           "test.test",
                                           (void **) &cached_collinfo,
                                           status),
                    status);
   bson_destroy (cached_collinfo);

   /* The next context enters the NEED_MONGO_MARKINGS state immediately. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}

static void
_test_encrypt_caches_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   /* The next context skips needing keys after being supplied mark documents.
    */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_random (_mongocrypt_tester_t *tester) {
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (tester, "./test/data/mongocryptd-reply-random.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_ctx_id (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx, *ctx2;

   crypt = _mongocrypt_tester_mongocrypt ();

   /* Two contexts should have different IDs */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx) == 1);

   ctx2 = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx2, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx2) == 2);

   /* Recreating a context results in a new ID */
   mongocrypt_ctx_destroy (ctx);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_id (ctx) == 3);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_ctx_destroy (ctx2);
   mongocrypt_destroy (crypt);
}


void
_mongocrypt_tester_install_ctx_encrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_encrypt_init);
   INSTALL_TEST (_test_encrypt_init);
   INSTALL_TEST (_test_encrypt_need_collinfo);
   INSTALL_TEST (_test_encrypt_need_markings);
   INSTALL_TEST (_test_encrypt_need_keys);
   INSTALL_TEST (_test_encrypt_ready);
   INSTALL_TEST (_test_key_missing_region);
   INSTALL_TEST (_test_view);
   INSTALL_TEST (_test_local_schema);
   INSTALL_TEST (_test_encrypt_caches_collinfo);
   INSTALL_TEST (_test_encrypt_caches_keys);
   INSTALL_TEST (_test_encrypt_random);
   INSTALL_TEST (_test_ctx_id);
}
