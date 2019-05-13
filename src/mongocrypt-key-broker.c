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


#include <stdlib.h>

#include <bson/bson.h>

#include "kms_message/kms_b64.h"

#include "mongocrypt.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-key-private.h"
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-log-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"

/* =======================
   Some utility functions.
   ======================= */

static bool
_alt_names_equal (const bson_value_t *a, const bson_value_t *b)
{
   BSON_ASSERT (a);
   BSON_ASSERT (b);

   /* We now only accept string names. */
   /* TODO CDRIVER-2988 error instead of asserting here. */
   BSON_ASSERT (a->value_type == BSON_TYPE_UTF8);
   BSON_ASSERT (b->value_type == BSON_TYPE_UTF8);

   return (0 == strcmp (a->value.v_utf8.str, b->value.v_utf8.str));
}

/* =========================================
   Key broker entry and convenience methods.
   ========================================= */

/* TODO CDRIVER-3112 consider changing the linked list impl. */

typedef struct __key_alt_name_t {
   struct __key_alt_name_t *next;
   bson_value_t value;
} _key_alt_name_t;

struct __mongocrypt_key_broker_entry_t {
   mongocrypt_status_t *status;
   _mongocrypt_key_state_t state;
   _mongocrypt_buffer_t key_id;
   _key_alt_name_t *key_alt_names;
   _mongocrypt_key_doc_t *key_returned;
   mongocrypt_kms_ctx_t kms;
   _mongocrypt_buffer_t decrypted_key_material;

   struct __mongocrypt_key_broker_entry_t *prev;
   struct __mongocrypt_key_broker_entry_t *next;
};

static _mongocrypt_key_broker_entry_t *
_kbe_new ()
{
   _mongocrypt_key_broker_entry_t *kbe = bson_malloc0 (sizeof (*kbe));
   return kbe;
}

static bool
_kbe_has_name (_mongocrypt_key_broker_entry_t *kbe, const bson_value_t *value)
{
   _key_alt_name_t *ptr;

   BSON_ASSERT (value);

   ptr = kbe->key_alt_names;
   while (ptr) {
      if (_alt_names_equal (&ptr->value, value)) {
         return true;
      }
      ptr = ptr->next;
   }

   return false;
}

static void
_kbe_add_name (_mongocrypt_key_broker_entry_t *kbe, const bson_value_t *value)
{
   _key_alt_name_t *name;

   BSON_ASSERT (value);

   /* Don't add the name if we already have it. */
   if (_kbe_has_name (kbe, value)) {
      return;
   }

   name = bson_malloc0 (sizeof (*name));
   bson_value_copy (value, &name->value);
   name->next = kbe->key_alt_names;
   kbe->key_alt_names = name;
}

static void
_kbe_set_id (_mongocrypt_key_broker_entry_t *kbe,
             const _mongocrypt_buffer_t *id)
{
   if (_mongocrypt_buffer_empty (id)) {
      return;
   }

   _mongocrypt_buffer_copy_to (id, &kbe->key_id);
}


static void
_kbe_destroy (_mongocrypt_key_broker_entry_t *kbe)
{
   _key_alt_name_t *ptr;
   _key_alt_name_t *next;

   ptr = kbe->key_alt_names;
   while (ptr) {
      next = ptr->next;
      bson_value_destroy (&ptr->value);
      bson_free (ptr);
      ptr = next;
   }

   mongocrypt_status_destroy (kbe->status);
   _mongocrypt_buffer_cleanup (&kbe->key_id);
   _mongocrypt_key_destroy (kbe->key_returned);
   _mongocrypt_kms_ctx_cleanup (&kbe->kms);
   _mongocrypt_buffer_cleanup (&kbe->decrypted_key_material);

   bson_free (kbe);
}

/* ============================
   Foreach methods and helpers.
   ============================ */

typedef bool (*_condition_fn_t) (_mongocrypt_key_broker_entry_t *kbe,
                                 void *ctx);

typedef bool (*_foreach_fn_t) (_mongocrypt_key_broker_entry_t *kbe, void *ctx);

/* Iterates over the entries in the key broker and calls
   the given callback function if the condition statement returns
   true. It is safe to remove the current element in the callback.

   If the foreach callback returns false when called on a match,
   iteration stops and we return false. */
static bool
_foreach_with_condition (_mongocrypt_key_broker_t *kb,
                         _condition_fn_t condition,
                         void *condition_ctx,
                         _foreach_fn_t foreach,
                         void *foreach_ctx)
{
   _mongocrypt_key_broker_entry_t *ptr;
   _mongocrypt_key_broker_entry_t *next;

   ptr = kb->kb_entry;

   while (ptr) {
      next = ptr->next;

      if (condition (ptr, condition_ctx)) {
         if (!foreach (ptr, foreach_ctx)) {
            return false;
         }
      }

      ptr = next;
   }

   return true;
}


typedef struct {
   _mongocrypt_key_broker_t *kb;
   _mongocrypt_key_broker_entry_t *mega_entry;
} _deduplicate_ctx_t;


/* This method is called with _foreach_with_condition to
   remove all matching elements from the key broker and condense
   them into one mega entry with the combined data. */
static bool
_deduplicate_entries (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _deduplicate_ctx_t *dedup_ctx;
   _key_alt_name_t *ptr;

   BSON_ASSERT (kbe);
   BSON_ASSERT (ctx);

   dedup_ctx = (_deduplicate_ctx_t *) ctx;

   /* Take the id, if there is one set. */
   _kbe_set_id (dedup_ctx->mega_entry, &kbe->key_id);

   /* Take all the key names that are set. */
   ptr = kbe->key_alt_names;
   while (ptr) {
      _kbe_add_name (dedup_ctx->mega_entry, &ptr->value);
      ptr = ptr->next;
   }

   /* Remove the old key entry. */
   BSON_ASSERT (kbe->state != KEY_DECRYPTING);
   if (kbe->prev) {
      kbe->prev->next = kbe->next;
   } else {
      /* if prev is NULL, should be at the head of the list. */
      dedup_ctx->kb->kb_entry = kbe->next;
      dedup_ctx->kb->decryptor_iter = kbe->next;
   }

   if (kbe->next) {
      kbe->next->prev = kbe->prev;
   }

   _kbe_destroy (kbe);

   return true;
}

typedef struct {
   int match_count;
} _count_ctx_t;

static bool
_count_matches (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _count_ctx_t *count_ctx;

   count_ctx = (_count_ctx_t *) ctx;
   count_ctx->match_count += 1;

   return true;
}

/* =================
   Matching helpers.
   ================= */

typedef struct {
   _mongocrypt_key_doc_t *key_doc;
   bool error;
} _key_doc_match_t;

static bool
_kbe_matches_key_doc (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _key_doc_match_t *helper;
   _mongocrypt_key_doc_t *key_doc;
   bson_iter_t iter;
   bson_t names;
   bool name_match = false;

   helper = (_key_doc_match_t *) ctx;
   key_doc = helper->key_doc;
   BSON_ASSERT (key_doc);

   /* A key doc has an ID and may also have keyAltNames.
      An entry matches this doc if it matches the key ID
      or any of the keyAltNames.

      If the key doc matches one or more keyAltNames, but
      does NOT have the same id, this is an error. */
   if (key_doc->has_alt_names) {
      bson_init_static (&names,
                        key_doc->key_alt_names.value.v_doc.data,
                        key_doc->key_alt_names.value.v_doc.data_len);

      bson_iter_init (&iter, &names);

      while (bson_iter_next (&iter)) {
         if (_kbe_has_name (kbe, bson_iter_value (&iter))) {
            name_match = true;
            break;
         }
      }
   }

   if (name_match) {
      /* If we have a name match and a returned key doc, then
    the doc must also match our id or it is an error. */
      if (kbe->key_returned) {
         if (0 !=
             _mongocrypt_buffer_cmp (&kbe->key_returned->id, &key_doc->id)) {
            helper->error = true;
            return false;
         }
      }

      /* We matched a name! Done. */
      return true;
   }

   if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, &key_doc->id)) {
      return true;
   }

   return false;
}

static bool
_kbe_matches_descriptor (_mongocrypt_key_broker_entry_t *kbe,
                         const void *key_descriptor,
                         bool is_alt_name)
{
   if (is_alt_name) {
      return _kbe_has_name (kbe, (bson_value_t *) key_descriptor);
   } else {
      _mongocrypt_buffer_t *key_id = (_mongocrypt_buffer_t *) key_descriptor;

      if (0 == _mongocrypt_buffer_cmp (&kbe->key_id, key_id)) {
         return true;
      }
   }

   return false;
}


static _mongocrypt_key_broker_entry_t *
_get_first_match_by_descriptor (_mongocrypt_key_broker_t *kb,
                                const void *key_descriptor,
                                bool is_alt_name)
{
   _mongocrypt_key_broker_entry_t *kbe;

   /* TODO CDRIVER-3113, use foreach helpers */
   for (kbe = kb->kb_entry; kbe; kbe = kbe->next) {
      if (_kbe_matches_descriptor (kbe, key_descriptor, is_alt_name)) {
         return kbe;
      }
   }

   return NULL;
}


static bool
_return_first_match (_mongocrypt_key_broker_entry_t *kbe, void *ctx)
{
   _mongocrypt_key_broker_entry_t **out;

   out = (_mongocrypt_key_broker_entry_t **) ctx;
   *out = kbe;

   return false;
}


static _mongocrypt_key_broker_entry_t *
_get_first_match_by_key_doc (_mongocrypt_key_broker_t *kb,
                             _mongocrypt_key_doc_t *key_doc)
{
   _key_doc_match_t match_helper;
   _mongocrypt_key_broker_entry_t *kbe = NULL;

   match_helper.key_doc = key_doc;

   _foreach_with_condition (
      kb, _kbe_matches_key_doc, &match_helper, _return_first_match, &kbe);

   return kbe;
}

/* =================
   External methods.
   ================= */

void
_mongocrypt_key_broker_init (_mongocrypt_key_broker_t *kb,
                             _mongocrypt_opts_t *opts,
                             _mongocrypt_cache_t *cache_key)
{
   memset (kb, 0, sizeof (*kb));
   kb->all_keys_added = false;
   kb->status = mongocrypt_status_new ();
   kb->crypt_opts = opts;
   kb->cache_key = cache_key;
}


bool
_mongocrypt_key_broker_has (_mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_state_t state)
{
   _mongocrypt_key_broker_entry_t *ptr;

   for (ptr = kb->kb_entry; ptr != NULL; ptr = ptr->next) {
      if (ptr->state == state) {
         return true;
      }
   }
   return false;
}


bool
_mongocrypt_key_broker_empty (_mongocrypt_key_broker_t *kb)
{
   return kb->kb_entry == NULL;
}


/* Returns false on error. */
static bool
_try_retrieving_from_cache (_mongocrypt_key_broker_t *kb,
                            _mongocrypt_key_broker_entry_t *kbe)
{
   _mongocrypt_cache_key_value_t *value;

   if (kbe->state != KEY_EMPTY) {
      mongocrypt_status_t *status;

      status = kb->status;
      CLIENT_ERR ("trying to retrieve key from cache in invalid state");
      return false;
   }

   if (!_mongocrypt_cache_get (
          kb->cache_key, &kbe->key_id, (void **) &value, kb->status)) {
      return false;
   }

   if (value) {
      kbe->state = KEY_DECRYPTED;
      _mongocrypt_key_doc_copy_to (&value->key_doc, &kbe->key_returned);
      _mongocrypt_buffer_copy_to (&value->decrypted_key_material,
                                  &kbe->decrypted_key_material);
      _mongocrypt_cache_key_value_destroy (value);
   }
   return true;
}


static bool
_store_to_cache (_mongocrypt_key_broker_t *kb,
                 _mongocrypt_key_broker_entry_t *kbe)
{
   _mongocrypt_cache_key_value_t *value;
   bool ret;

   if (kbe->state != KEY_DECRYPTED) {
      mongocrypt_status_t *status = kb->status;
      CLIENT_ERR ("cannot cache non-decrypted key");
      return false;
   }

   value = _mongocrypt_cache_key_value_new (&kbe->key_returned,
                                            &kbe->decrypted_key_material);
   ret = _mongocrypt_cache_add_stolen (
      kb->cache_key, &kbe->key_id, value, kb->status);
   return ret;

static void
_add_new_key_entry (_mongocrypt_key_broker_t *kb,
                    _mongocrypt_key_broker_entry_t *kbe)
{
   kbe->state = KEY_EMPTY;
   if (kb->kb_entry) {
      kb->kb_entry->prev = kbe;
   }
   kbe->next = kb->kb_entry;
   kbe->prev = NULL;
   kb->kb_entry = kbe;
   kb->decryptor_iter = kbe;
}


bool
_mongocrypt_key_broker_add_name (_mongocrypt_key_broker_t *kb,
                                 const bson_value_t *key_alt_name)
{
   _mongocrypt_key_broker_entry_t *kbe;
   mongocrypt_status_t *status = kb->status;

   BSON_ASSERT (key_alt_name);
   if (_mongocrypt_key_broker_has (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new keys");
      return false;
   }

   /* If we already have this key, return */
   if (_get_first_match_by_descriptor (kb, key_alt_name, true)) {
      return true;
   }

   /* TODO CDRIVER-2951 check if we have this key cached. */
   kbe = _kbe_new ();
   _kbe_add_name (kbe, key_alt_name);
   _add_new_key_entry (kb, kbe);

   return true;
}


bool
_mongocrypt_key_broker_add_id (_mongocrypt_key_broker_t *kb,
                               const _mongocrypt_buffer_t *key_id)
{
   _mongocrypt_key_broker_entry_t *kbe = NULL;
   mongocrypt_status_t *status = kb->status;

   status = kb->status;
   if (key_id->subtype != BSON_SUBTYPE_UUID) {
      CLIENT_ERR ("expected UUID for key_id");
      return false;
   }

   if (_mongocrypt_key_broker_has (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new keys");
      return false;
   }

   /* If we already have this key, return */
   if (_get_first_match_by_descriptor (kb, (void *) key_id, false)) {
      return true;
   }

   /* TODO CDRIVER-2951 check if we have this key cached. */
   kbe = _kbe_new ();
   _kbe_set_id (kbe, key_id);
   _add_new_key_entry (kb, kbe);

   if (!_try_retrieving_from_cache (kb, kbe)) {
      return false;
   }

   return true;
}


bool
_mongocrypt_key_broker_add_test_key (_mongocrypt_key_broker_t *kb,
                                     const _mongocrypt_buffer_t *key_id)
{
   BSON_ASSERT (kb);

   if (!_mongocrypt_key_broker_add_id (kb, key_id)) {
      return false;
   }

   /* The first entry in the list should be our new one. Modify
      it so that it is in a decrypted state for testing. Use the
      key_id as the decrypted material, because it doesn't matter. */
   BSON_ASSERT (kb->kb_entry);
   kb->kb_entry->state = KEY_DECRYPTED;
   _mongocrypt_buffer_copy_to (&kb->kb_entry->key_id,
                               &kb->kb_entry->decrypted_key_material);

   return true;
}


bool
_mongocrypt_key_broker_add_doc (_mongocrypt_key_broker_t *kb,
                                const _mongocrypt_buffer_t *doc)
{
   _key_doc_match_t match_helper;
   _mongocrypt_kms_provider_t masterkey_provider;
   _count_ctx_t count_ctx;
   mongocrypt_status_t *status;
   bson_t doc_bson;
   _mongocrypt_key_doc_t *key = NULL;
   _mongocrypt_key_broker_entry_t *kbe = NULL;
   bool ret;

   BSON_ASSERT (kb);
   ret = false;
   status = kb->status;

   if (_mongocrypt_key_broker_has (kb, KEY_DECRYPTING)) {
      CLIENT_ERR ("already decrypting; too late to add new key docs");
      return false;
   }

   if (!doc) {
      CLIENT_ERR ("invalid key");
      goto done;
   }

   /* First, parse the key document. */
   key = _mongocrypt_key_new ();
   _mongocrypt_buffer_to_bson (doc, &doc_bson);
   if (!_mongocrypt_key_parse_owned (&doc_bson, key, status)) {
      goto done;
   }

   /* Check that the returned key doc's provider matches. */
   masterkey_provider = key->masterkey_provider;
   if (0 == (masterkey_provider & kb->crypt_opts->kms_providers)) {
      CLIENT_ERR (
         "client not configured with KMS provider necessary to decrypt");
      goto done;
   }

   /* Next, ensure that we have at least one matching key broker
      entry for this key doc. */
   match_helper.key_doc = key;
   match_helper.error = false;
   count_ctx.match_count = 0;
   _foreach_with_condition (
      kb, _kbe_matches_key_doc, &match_helper, _count_matches, &count_ctx);

   if (match_helper.error) {
      CLIENT_ERR ("matching keyAltNames with non-matching id");
      goto done;
   }

   if (count_ctx.match_count == 0) {
      CLIENT_ERR ("no matching key in the key broker");
      goto done;
   }

   if (count_ctx.match_count > 1) {
      _deduplicate_ctx_t dedup_ctx;

      dedup_ctx.kb = kb;
      dedup_ctx.mega_entry = _kbe_new ();

      /* Now, deduplicate all matches by making one new entry
    that contains the id and all the collected key names. */
      _foreach_with_condition (kb,
                               _kbe_matches_key_doc,
                               &match_helper,
                               _deduplicate_entries,
                               &dedup_ctx);

      /* Then, add the mega entry back into the key broker. */
      kbe = dedup_ctx.mega_entry;
      kbe->next = kb->kb_entry;
      kbe->prev = NULL;
      kb->kb_entry = kbe;
      kb->decryptor_iter = kbe;
   } else {
      /* If we just found a single matching key, use it as-is. */
      kbe = _get_first_match_by_key_doc (kb, key);
      BSON_ASSERT (kbe);
   }

   /* We will now take ownership of the key document. */
   kbe->key_returned = key;
   key = NULL;

   kbe->state = KEY_ENCRYPTED;

   /* Check that the mongocrypt_t was configured with the KMS
      provider needed. */
   if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_LOCAL) {
      bool crypt_ret;
      uint32_t bytes_written;

      kbe->decrypted_key_material.len = _mongocrypt_calculate_plaintext_len (
         kbe->key_returned->key_material.len);
      kbe->decrypted_key_material.data =
         bson_malloc (kbe->decrypted_key_material.len);
      kbe->decrypted_key_material.owned = true;

      crypt_ret = _mongocrypt_do_decryption (NULL /* associated data. */,
                                             &kb->crypt_opts->kms_local_key,
                                             &kbe->key_returned->key_material,
                                             &kbe->decrypted_key_material,
                                             &bytes_written,
                                             status);

      if (!crypt_ret) {
         goto done;
      }
      kbe->state = KEY_DECRYPTED;
      _store_to_cache (kb, kbe);

   } else if (masterkey_provider == MONGOCRYPT_KMS_PROVIDER_AWS) {
      if (!_mongocrypt_kms_ctx_init_aws_decrypt (
	 &kbe->kms, kb->crypt_opts, kbe->key_returned, kbe)) {
         mongocrypt_kms_ctx_status (&kbe->kms, status);

         goto done;
      }
   } else {
      CLIENT_ERR ("unrecognized kms provider");
      goto done;
   }

   ret = true;

done:
   _mongocrypt_key_destroy (key);

   return ret;
}


bool
_mongocrypt_key_broker_done_adding_docs (_mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;

   BSON_ASSERT (kb);
   status = kb->status;

   if (_mongocrypt_key_broker_has (kb, KEY_EMPTY)) {
      CLIENT_ERR ("client did not provide all keys");
      return false;
   }

   kb->all_keys_added = true;

   return true;
}


mongocrypt_kms_ctx_t *
_mongocrypt_key_broker_next_kms (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);

   if (!_mongocrypt_key_broker_has (kb, KEY_DECRYPTING)) {
      kb->decryptor_iter = kb->kb_entry;
   }

   kbe = kb->decryptor_iter;

   while (kbe && kbe->state != KEY_ENCRYPTED) {
      kbe = kbe->next;
   }

   if (kbe) {
      kbe->state = KEY_DECRYPTING;
      kb->decryptor_iter = kbe->next;
      return &kbe->kms;
   } else {
      kb->decryptor_iter = NULL;
      return NULL;
   }
}


bool
_mongocrypt_key_broker_kms_done (_mongocrypt_key_broker_t *kb)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbe;

   status = kb->status;
   for (kbe = kb->kb_entry; kbe != NULL; kbe = kbe->next) {
      if (kbe->state != KEY_DECRYPTING) {
         /* TODO: don't error based on err_on_missing flag. */
         CLIENT_ERR ("key broker still contains encrypted keys");
         return false;
      }

      if (!_mongocrypt_kms_ctx_result (&kbe->kms,
                                       &kbe->decrypted_key_material)) {
         /* Always fatal. Key attempted to decrypt but failed. */
         mongocrypt_kms_ctx_status (&kbe->kms, status);
         return false;
      }
      kbe->state = KEY_DECRYPTED;
      _store_to_cache (kb, kbe);
   }
   return true;
}


static bool
_get_decrypted_key (_mongocrypt_key_broker_t *kb,
                    const void *key_descriptor,
                    _mongocrypt_buffer_t *out,
                    bool is_alt_name)
{
   mongocrypt_status_t *status;
   _mongocrypt_key_broker_entry_t *kbe;

   BSON_ASSERT (kb);
   status = kb->status;

   kbe = _get_first_match_by_descriptor (kb, key_descriptor, is_alt_name);
   if (!kbe) {
      CLIENT_ERR ("no matching key found");
      return false;
   }

   if (kbe->state != KEY_DECRYPTED) {
      CLIENT_ERR ("key found, but material not decrypted");
      return false;
   }

   _mongocrypt_buffer_init (out);
   out->data = kbe->decrypted_key_material.data;
   out->len = kbe->decrypted_key_material.len;

   return true;
}


bool
_mongocrypt_key_broker_decrypted_key_by_id (_mongocrypt_key_broker_t *kb,
                                            const _mongocrypt_buffer_t *key_id,
                                            _mongocrypt_buffer_t *out)
{
   return _get_decrypted_key (kb, (void *) key_id, out, false);
}


bool
_mongocrypt_key_broker_decrypted_key_by_name (_mongocrypt_key_broker_t *kb,
                                              const bson_value_t *key_alt_name,
                                              _mongocrypt_buffer_t *out)
{
   return _get_decrypted_key (kb, key_alt_name, out, true);
}


bool
_mongocrypt_key_broker_filter (_mongocrypt_key_broker_t *kb,
                               mongocrypt_binary_t *out)
{
   _mongocrypt_key_broker_entry_t *iter;
   _key_alt_name_t *ptr;
   int name_index = 0;
   int id_index = 0;
   bson_t ids, names;
   bson_t *filter;

   BSON_ASSERT (kb);

   if (!_mongocrypt_buffer_empty (&kb->filter)) {
      _mongocrypt_buffer_to_binary (&kb->filter, out);
      return true;
   }

   if (!_mongocrypt_key_broker_has (kb, KEY_EMPTY)) {
      /* no keys need to be fetched. */
      /* TODO: double check this is what we want to do here. */
      out->data = NULL;
      out->len = 0;
      return true;
   }

   bson_init (&names);
   bson_init (&ids);

   for (iter = kb->kb_entry; iter != NULL; iter = iter->next) {
      if (iter->state != KEY_EMPTY) {
         continue;
      }

      if (!_mongocrypt_buffer_empty (&iter->key_id)) {
         /* Collect key_ids in "ids" */
         char *key_str;

         key_str = bson_strdup_printf ("%d", id_index++);
         _mongocrypt_buffer_append (
            &iter->key_id, &ids, key_str, (uint32_t) strlen (key_str));

         bson_free (key_str);
      }

      /* Collect key alt names in "names" */
      ptr = iter->key_alt_names;
      while (ptr) {
         char *key_str;

         key_str = bson_strdup_printf ("%d", name_index++);
         bson_append_value (
            &names, key_str, (uint32_t) strlen (key_str), &ptr->value);

         bson_free (key_str);
         ptr = ptr->next;
      }
   }

   /*
    * This is our final query:
    * { $or: [ { _id: { $in : [ids] }},
    *          { keyAltName : { $in : [names] }} ] }
    */

   filter = BCON_NEW ("$or",
                      "[",
                      "{",
                      "_id",
                      "{",
                      "$in",
                      BCON_ARRAY (&ids),
                      "}",
                      "}",
                      "{",
                      "keyAltName",
                      "{",
                      "$in",
                      BCON_ARRAY (&names),
                      "}",
                      "}",
                      "]");

   _mongocrypt_buffer_steal_from_bson (&kb->filter, filter);
   _mongocrypt_buffer_to_binary (&kb->filter, out);

   return true;
}


bool
_mongocrypt_key_broker_status (_mongocrypt_key_broker_t *kb,
                               mongocrypt_status_t *out)
{
   BSON_ASSERT (kb);

   if (!mongocrypt_status_ok (kb->status)) {
      _mongocrypt_status_copy_to (kb->status, out);
      return false;
   }

   return true;
}

void
_mongocrypt_key_broker_cleanup (_mongocrypt_key_broker_t *kb)
{
   _mongocrypt_key_broker_entry_t *kbe, *tmp;

   if (!kb) {
      return;
   }

   kbe = kb->kb_entry;

   while (kbe) {
      tmp = kbe->next;
      _kbe_destroy (kbe);
      kbe = tmp;
   }

   kb->kb_entry = NULL;

   mongocrypt_status_destroy (kb->status);
   _mongocrypt_buffer_cleanup (&kb->filter);
}
