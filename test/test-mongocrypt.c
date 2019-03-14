#include <stdio.h>
#include <stdlib.h>

#include <bson/bson.h>
#include <mongocrypt.h>
#include <mongocrypt-crypto-private.h>
#include <mongocrypt-decryptor.h>
#include <mongocrypt-decryptor-private.h>
#include <mongocrypt-encryptor.h>
#include <mongocrypt-key-broker.h>
#include <mongocrypt-key-cache-private.h>
#include <mongocrypt-log-private.h>
#include <mongocrypt-private.h>


#define ASSERT_OR_PRINT_MSG(_statement, msg)          \
   do {                                               \
      if (!(_statement)) {                            \
         fprintf (stderr,                             \
                  "FAIL:%s:%d  %s()\n  %s\n  %s\n\n", \
                  __FILE__,                           \
                  __LINE__,                           \
                  BSON_FUNC,                          \
                  #_statement,                        \
                  (msg));                             \
         fflush (stderr);                             \
         abort ();                                    \
      }                                               \
   } while (0)

#define ASSERT_OR_PRINT(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, mongocrypt_status_message (_err))

#define ASSERT_OR_PRINT_BSON(_statement, _err) \
   ASSERT_OR_PRINT_MSG (_statement, _err.message)

#define ASSERT(_statement) \
   ASSERT_OR_PRINT_MSG (_statement, "")

/* read the schema file, create mongocrypt_t handle with options. */
static void
_setup (mongocrypt_opts_t *opts, bson_t *one_schema)
{
   bson_json_reader_t *reader;
   bson_error_t error;
   int status;
   bson_iter_t iter;
   bson_t schemas;
   const uint8_t *data;
   uint32_t len;
   bson_t temp;

   reader = bson_json_reader_new_from_file ("./test/schema.json", &error);
   ASSERT_OR_PRINT_BSON (reader, error);

   bson_init (&schemas);
   status = bson_json_reader_read (reader, &schemas, &error);
   ASSERT_OR_PRINT_BSON (status == 1, error);

   printf ("schema: %s\n", tmp_json (&schemas));

   BSON_ASSERT (bson_iter_init_find (&iter, &schemas, "test.crypt"));
   BSON_ASSERT (BSON_ITER_HOLDS_DOCUMENT (&iter));
   bson_iter_recurse (&iter, &iter);
   BSON_ASSERT (bson_iter_find (&iter, "schema"));
   bson_iter_document (&iter, &len, &data);
   bson_init_static (&temp, data, len);
   bson_copy_to (&temp, one_schema);
   bson_destroy (&schemas);
   printf ("schema: %s\n", tmp_json (one_schema));

   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_ACCESS_KEY_ID, getenv ("AWS_ACCESS_KEY_ID"));
   mongocrypt_opts_set_opt (
      opts, MONGOCRYPT_AWS_SECRET_ACCESS_KEY, getenv ("AWS_SECRET_ACCESS_KEY"));
   mongocrypt_opts_set_opt (opts, MONGOCRYPT_AWS_REGION, getenv ("AWS_REGION"));

   bson_json_reader_destroy (reader);
}

/* Return a repeated character with no null terminator. */
static char *
_repeat_char (char c, uint32_t times)
{
   char *result;
   uint32_t i;

   result = bson_malloc (times);
   for (i = 0; i < times; i++) {
      result[i] = c;
   }

   return result;
}

static void
_test_roundtrip (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key = {0}, iv = {0}, associated_data = {0},
                        plaintext = {0}, ciphertext = {0}, decrypted = {0};
   uint32_t bytes_written;
   bool ret;

   plaintext.data = (uint8_t *) "test";
   plaintext.len = 5; /* include NULL. */

   ciphertext.len = _mongocrypt_calculate_ciphertext_len (5);
   ciphertext.data = bson_malloc (ciphertext.len);
   ciphertext.owned = true;

   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   key.data = (uint8_t *) _repeat_char ('k', 64);
   key.len = 64;
   key.owned = true;

   iv.data = (uint8_t *) _repeat_char ('i', 16);
   iv.len = 16;
   iv.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);

   BSON_ASSERT (bytes_written == ciphertext.len);

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (ret);


   BSON_ASSERT (bytes_written == plaintext.len);
   decrypted.len = bytes_written;
   BSON_ASSERT (0 == strcmp ((char *) decrypted.data, (char *) plaintext.data));

   /* Modify a bit in the ciphertext hash to ensure HMAC integrity check. */
   ciphertext.data[ciphertext.len - 1] &= 1;

   _mongocrypt_buffer_cleanup (&decrypted);
   decrypted.len = _mongocrypt_calculate_plaintext_len (ciphertext.len);
   decrypted.data = bson_malloc (decrypted.len);
   decrypted.owned = true;

   ret = _mongocrypt_do_decryption (
      &associated_data, &key, &ciphertext, &decrypted, &bytes_written, status);
   BSON_ASSERT (!ret);
   BSON_ASSERT (0 == strcmp (status->message, "HMAC validation failure"));

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&decrypted);
   _mongocrypt_buffer_cleanup (&ciphertext);
   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
}


static void
_init_buffer (_mongocrypt_buffer_t *out, const char *hex_string)
{
   int i;

   out->len = strlen (hex_string) / 2;
   out->data = bson_malloc (out->len);
   out->owned = true;
   for (i = 0; i < out->len; i++) {
      int tmp;
      BSON_ASSERT (sscanf (hex_string + (2 * i), "%02x", &tmp));
      *(out->data + i) = (uint8_t) tmp;
   }
}


/* From [MCGREW], see comment at the top of this file. */
static void
_test_mcgrew (void)
{
   mongocrypt_status_t *status;
   _mongocrypt_buffer_t key, iv, associated_data, plaintext,
      ciphertext_expected, ciphertext_actual;
   uint32_t bytes_written;
   bool ret;

   _init_buffer (&key,
                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1"
                 "b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
                 "3738393a3b3c3d3e3f");
   _init_buffer (&iv, "1af38c2dc2b96ffdd86694092341bc04");
   _init_buffer (&plaintext,
                 "41206369706865722073797374656d206d757374206e6f742"
                 "0626520726571756972656420746f20626520736563726574"
                 "2c20616e64206974206d7573742062652061626c6520746f2"
                 "066616c6c20696e746f207468652068616e6473206f662074"
                 "686520656e656d7920776974686f757420696e636f6e76656"
                 "e69656e6365");
   _init_buffer (&associated_data,
                 "546865207365636f6e64207072696e6369706c65206"
                 "f662041756775737465204b6572636b686f666673");
   _init_buffer (&ciphertext_expected,
                 "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10f"
                 "fbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e"
                 "9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75"
                 "c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae4"
                 "96b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930"
                 "930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a81"
                 "6dbc1b267761955bc5");

   ciphertext_actual.len = _mongocrypt_calculate_ciphertext_len (plaintext.len);
   ciphertext_actual.data = bson_malloc (ciphertext_actual.len);
   ciphertext_actual.owned = true;

   status = mongocrypt_status_new ();
   ret = _mongocrypt_do_encryption (&iv,
                                    &associated_data,
                                    &key,
                                    &plaintext,
                                    &ciphertext_actual,
                                    &bytes_written,
                                    status);
   BSON_ASSERT (ret);
   BSON_ASSERT (ciphertext_actual.len == ciphertext_expected.len);
   BSON_ASSERT (0 == memcmp (ciphertext_actual.data,
                             ciphertext_expected.data,
                             ciphertext_actual.len));

   _mongocrypt_buffer_cleanup (&key);
   _mongocrypt_buffer_cleanup (&iv);
   _mongocrypt_buffer_cleanup (&plaintext);
   _mongocrypt_buffer_cleanup (&associated_data);
   _mongocrypt_buffer_cleanup (&ciphertext_expected);
   _mongocrypt_buffer_cleanup (&ciphertext_actual);
   mongocrypt_status_destroy (status);
}


typedef struct {
   mongocrypt_log_level_t expected_level;
} log_test_ctx_t;


static void
_test_log_fn (mongocrypt_log_level_t level, const char *message, void *ctx_void)
{
   log_test_ctx_t *ctx = (log_test_ctx_t *) ctx_void;
   BSON_ASSERT (level == ctx->expected_level);
   BSON_ASSERT (0 == strcmp (message, "test"));
}


/* Test a custom log handler on all log levels except for trace. */
static void
_test_log (void)
{
   log_test_ctx_t log_ctx = {0};
   mongocrypt_log_level_t levels[] = {MONGOCRYPT_LOG_LEVEL_FATAL,
                                      MONGOCRYPT_LOG_LEVEL_ERROR,
                                      MONGOCRYPT_LOG_LEVEL_WARNING,
                                      MONGOCRYPT_LOG_LEVEL_INFO};
   int i;
   mongocrypt_t *crypt;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   crypt = mongocrypt_new (NULL, status);
   /* Test logging with a custom handler messages. */
   _mongocrypt_log_set_fn (&crypt->log, _test_log_fn, &log_ctx);
   for (i = 0; i < sizeof (levels) / sizeof (*levels); i++) {
      log_ctx.expected_level = levels[i];
      _mongocrypt_log (&crypt->log, levels[i], "test");
   }

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static mongocrypt_binary_t *
_load_json_from_file (mongocrypt_t *crypt, const char *path)
{
   bson_error_t error;
   bson_json_reader_t *reader;
   bson_t out;
   bool ret;
   mongocrypt_binary_t *to_return;

   reader = bson_json_reader_new_from_file (path, &error);
   ASSERT_OR_PRINT_BSON (reader, error);

   bson_init (&out);
   ret = bson_json_reader_read (reader, &out, &error);
   ASSERT_OR_PRINT_BSON (ret, error);
   CRYPT_TRACEF (&crypt->log, "read BSON from %s: %s", path, tmp_json (&out));
   to_return = mongocrypt_binary_new ();
   to_return->data = bson_destroy_with_steal (&out, true, &to_return->len);
   return to_return;
}

static mongocrypt_binary_t *
_load_http_from_file (mongocrypt_t *crypt, const char *path)
{
   bson_error_t error;
   int fd;
   bool ret;
   char *out;
   mongocrypt_binary_t *to_return;
   int n_read;
   int filesize;
   char buf[512];
   int slen;
   int i;

   filesize = 0;
   out = NULL;
   fd = open (path, O_RDONLY);
   while ((n_read = read (fd, buf, sizeof (buf))) > 0) {
      filesize += n_read;
      /* Append buf. Performance does not matter. */
      out = bson_realloc (out, filesize);
      memcpy (out + (filesize - n_read), buf, n_read);
   }

   if (n_read < 0) {
      fprintf (stderr, "failed to read %s\n", path);
      abort ();
   }

   close (fd);

   /* copy and fix newlines */
   to_return = mongocrypt_binary_new ();
   /* allocate twice the size since \n may become \r\n */
   to_return->data = bson_malloc0 (filesize * 2);
   to_return->len = 0;
   for (i = 0; i < filesize; i++) {
      if (out[i] == '\n' && out[i - 1] != '\r') {
         to_return->data[to_return->len++] = '\r';
      }
      to_return->data[to_return->len++] = out[i];
   }

   bson_free (out);

   if (filesize > 0) {
      CRYPT_TRACEF (
         &crypt->log, "read http request from %s: %s", path, to_return->data);
   }

   return to_return;
}

static mongocrypt_binary_t *
load_key_document (mongocrypt_t *crypt)
{
   return _load_json_from_file (crypt, "./test/example/key-document.json");
}

static mongocrypt_binary_t *
load_kms_response (mongocrypt_t *crypt)
{
   return _load_http_from_file (crypt, "./test/example/kms-reply.txt");
}

static mongocrypt_binary_t *
load_list_collections_response (mongocrypt_t *crypt)
{
   return _load_json_from_file (crypt, "./test/example/list-collections-reply.json");
}

static mongocrypt_binary_t *
load_marked_reply (mongocrypt_t *crypt)
{
   return _load_json_from_file (crypt, "./test/example/marked-reply.json");
}

static mongocrypt_binary_t *
load_example_command (mongocrypt_t *crypt)
{
   return _load_json_from_file (crypt, "./test/example/command.json");
}

static void
key_broker_fetch_all_keys (mongocrypt_t *crypt, mongocrypt_key_broker_t *kb)
{
   mongocrypt_key_decryptor_t *key_decryptor;
   mongocrypt_binary_t *kms_response;
   mongocrypt_binary_t *key_doc;
   const mongocrypt_binary_t *filter;
   bson_t tmp;
   bson_iter_t iter;
   int bytes_needed;

   filter = mongocrypt_key_broker_get_key_filter (kb, NULL);
   ASSERT (filter);

   /* Check that the filter has the form { _id: $in : [ ] } */
   mongocrypt_binary_to_bson (filter, &tmp);
   bson_iter_init (&iter, &tmp);
   BSON_ASSERT (bson_iter_find_descendant (&iter, "_id.$in.0", &iter));
   /* Add key document (generated by python script) */
   key_doc = load_key_document(crypt);
   ASSERT (mongocrypt_key_broker_add_key (kb, key_doc, NULL));

   /* The test input should only require one key! */
   ASSERT (mongocrypt_key_broker_done_adding_keys (kb, NULL));
   key_decryptor = mongocrypt_key_broker_next_decryptor (kb, NULL);
   ASSERT (!mongocrypt_key_broker_next_decryptor (kb, NULL));

   bytes_needed = mongocrypt_key_decryptor_bytes_needed (key_decryptor, 1024);

   /* Feed the whole reply at once */
   kms_response = load_kms_response (crypt);
   BSON_ASSERT (mongocrypt_key_decryptor_feed (key_decryptor,
					       kms_response,
					       NULL));
   ASSERT (mongocrypt_key_decryptor_bytes_needed (key_decryptor, 1024) == 0);

   ASSERT (mongocrypt_key_broker_add_decrypted_key (kb,
						    key_decryptor,
						    NULL));

   mongocrypt_binary_destroy (kms_response);
   mongocrypt_binary_destroy (key_doc);

   return;
}

static void
assert_error (mongocrypt_decryptor_t *decryptor, mongocrypt_decryptor_state_t state)
{
   ASSERT (state == MONGOCRYPT_DECRYPTOR_STATE_ERROR);
   ASSERT (mongocrypt_decryptor_state (decryptor) ==
	   MONGOCRYPT_DECRYPTOR_STATE_ERROR);
   ASSERT (!mongocrypt_status_ok (mongocrypt_decryptor_status (decryptor)));
}

static void
assert_ok_with_state (mongocrypt_decryptor_t *decryptor,
		      mongocrypt_decryptor_state_t state,
		      mongocrypt_decryptor_state_t goal_state)
{
   ASSERT (state == goal_state);
   ASSERT (mongocrypt_decryptor_state (decryptor) == goal_state);
   ASSERT (mongocrypt_status_ok (mongocrypt_decryptor_status (decryptor)));
}

static void
reset_decryptor (mongocrypt_decryptor_t *decryptor,
		 mongocrypt_decryptor_state_t state)
{
   mongocrypt_status_reset (mongocrypt_decryptor_status (decryptor));
   decryptor->state = state;

   switch (state) {
   case MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC:
      mongocrypt_binary_destroy (decryptor->encrypted_doc);
      mongocrypt_binary_destroy (decryptor->decrypted_doc);
      decryptor->encrypted_doc = NULL;
      decryptor->decrypted_doc = NULL;
      break;
   case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS:
      // reset key broker?
      break;
   case MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION:
      mongocrypt_binary_destroy (decryptor->decrypted_doc);
      decryptor->decrypted_doc = NULL;
      break;
   case MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED:
      mongocrypt_binary_destroy (decryptor->decrypted_doc);
      decryptor->decrypted_doc = NULL;
      break;
   case MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED:
      break;
   default:
      break;
   }
}

static void
_test_decryptor (void)
{
   mongocrypt_decryptor_state_t state;
   mongocrypt_t *mongocrypt;
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_key_broker_t *kb;
   mongocrypt_status_t *status;
   mongocrypt_status_t *decryptor_status;
   /* TODO get AWS credentials from Kevin and make these real */
   mongocrypt_binary_t *bad_doc = NULL;
   mongocrypt_binary_t *plaintext_doc = NULL;
   mongocrypt_binary_t *encrypted_doc = NULL;

   status = mongocrypt_status_new ();
   mongocrypt = mongocrypt_new (NULL, status);

   /* mongocrypt_decryptor_new () */
   decryptor = mongocrypt_decryptor_new (mongocrypt);
   decryptor_status = mongocrypt_decryptor_status (decryptor);
   ASSERT (mongocrypt_decryptor_state (decryptor) ==
	   MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC);
   ASSERT (mongocrypt_status_ok (decryptor_status));
   ASSERT (!mongocrypt_decryptor_decrypted_cmd (decryptor));
   ASSERT (!mongocrypt_status_ok (decryptor_status));

   reset_decryptor (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC);

   /* mongocrypt_decryptor_add_doc () */
   /* NULL document */
   state = mongocrypt_decryptor_add_doc (decryptor, NULL);
   assert_error (decryptor, state);
   reset_decryptor (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC);

   /* invalid document with malformatted ciphertext */
   state = mongocrypt_decryptor_add_doc (decryptor, bad_doc);
   assert_error (decryptor, state);
   reset_decryptor (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC);

   /* valid document with no ciphertexts */
   state = mongocrypt_decryptor_add_doc (decryptor, plaintext_doc);
   assert_ok_with_state (decryptor,
			 state,
			 MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED);
   ASSERT (!decryptor->encrypted_doc);
   ASSERT (mongocrypt_decryptor_decrypted_cmd (decryptor) == plaintext_doc);

   reset_decryptor (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC);

   /* valid document with ciphertexts */
   state = mongocrypt_decryptor_add_doc (decryptor, encrypted_doc);
   assert_ok_with_state (decryptor,
			 state,
			 MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);
   ASSERT (decryptor->encrypted_doc == encrypted_doc);

   /* mongocrypt_decryptor_get_key_broker () */
   kb = mongocrypt_decryptor_get_key_broker (decryptor);
   ASSERT (kb);
   assert_ok_with_state (decryptor,
			 MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS,
			 MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);

   /* mongocrypt_decryptor_key_broker_done () */

   /* key broker that still has empty keys */
   state = mongocrypt_decryptor_key_broker_done (decryptor);
   assert_error (decryptor, state);
   reset_decryptor (decryptor, MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS);

   /* key broker with all keys fetched */
   key_broker_fetch_all_keys (mongocrypt, kb);
   state = mongocrypt_decryptor_key_broker_done (decryptor);
   assert_ok_with_state (decryptor,
			 state,
			 MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION);

   /* mongocrypt_decryptor_decrypt () */
   state = mongocrypt_decryptor_decrypt (decryptor);
   assert_ok_with_state (decryptor,
			 state,
			 MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED);
   ASSERT (mongocrypt_decryptor_decrypted_cmd (decryptor));

   mongocrypt_status_destroy (status);
   mongocrypt_decryptor_destroy (decryptor);
   mongocrypt_destroy (mongocrypt);
}

static void
_test_encryptor (void)
{
   mongocrypt_status_t *status;
   mongocrypt_binary_t *command;
   mongocrypt_binary_t *list_collections_reply;
   mongocrypt_binary_t *marked_reply;
   mongocrypt_key_broker_t *kb;
   mongocrypt_t *mongocrypt;
   mongocrypt_encryptor_t *encryptor;
   bson_t tmp;
   _mongocrypt_buffer_t tmp_buf;
   bson_iter_t iter;

   status = mongocrypt_status_new ();

   mongocrypt = mongocrypt_new (NULL, status);

   list_collections_reply = load_list_collections_response (mongocrypt);
   command = load_example_command (mongocrypt);
   marked_reply = load_marked_reply (mongocrypt);

   encryptor = mongocrypt_encryptor_new (mongocrypt);

   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS);
   mongocrypt_encryptor_add_ns (encryptor, "test.test");

   /* mongocrypt_encryptor_add_ns () */
   mongocrypt_encryptor_add_ns (encryptor, "test.test");
   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA);

   /* mongocrypt_encryptor_add_collection_info () */
   mongocrypt_encryptor_add_collection_info (
      encryptor, list_collections_reply);
   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS);

   /* mongocrypt_encryptor_add_markings () */
   mongocrypt_encryptor_add_markings (encryptor, marked_reply);
   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS);

   /* mongocrypt_encryptor_get_key_broker () */
   kb = mongocrypt_encryptor_get_key_broker (encryptor);
   key_broker_fetch_all_keys (mongocrypt, kb);
   mongocrypt_encryptor_key_broker_done (encryptor);

   /* mongocrypt_encryptor_key_broker_done () */
   BSON_ASSERT (mongocrypt_encryptor_state (encryptor) ==
                MONGOCRYPT_ENCRYPTOR_STATE_NEED_ENCRYPTION);

   /* mongocrypt_encryptor_encrypt () */
   mongocrypt_encryptor_encrypt (encryptor);

   _mongocrypt_unowned_buffer_from_binary (
      mongocrypt_encryptor_encrypted_cmd (encryptor), &tmp_buf);
   _mongocrypt_buffer_to_unowned_bson (&tmp_buf, &tmp);
   CRYPT_TRACEF (&mongocrypt->log, "encrypted to: %s", tmp_json (&tmp));

   mongocrypt_destroy (mongocrypt);
   mongocrypt_binary_destroy (command);
   mongocrypt_binary_destroy (marked_reply);
   mongocrypt_binary_destroy (list_collections_reply);
}

static void
_init_buffer_with_count (_mongocrypt_buffer_t *out, uint32_t count)
{
   out->len = count;
   out->data = bson_malloc0 (out->len);
   out->owned = true;
}

static void
_test_random_generator (void)
{
   _mongocrypt_buffer_t out;
   mongocrypt_status_t *status;
   uint32_t count = 32;
   int mid = count / 2;
   char zero[count];

   /* _mongocrypt_random handles the case where the count size is greater
    * than the buffer by throwing an error. Because of that, no additional tests
    * for this case is needed here. */

   memset (zero, 0, count);
   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, count);

   BSON_ASSERT (_mongocrypt_random (&out, status, count));
   BSON_ASSERT (0 != memcmp (zero, out.data, count)); /* initialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);

   status = mongocrypt_status_new ();
   _init_buffer_with_count (&out, count);

   BSON_ASSERT (_mongocrypt_random (&out, status, mid));
   BSON_ASSERT (0 != memcmp (zero, out.data, mid));       /* initialized */
   BSON_ASSERT (0 == memcmp (zero, out.data + mid, mid)); /* uninitialized */

   mongocrypt_status_destroy (status);
   _mongocrypt_buffer_cleanup (&out);
}

#define ADD_TEST(fn)                          \
   do {                                       \
      bool found = true;                      \
      if (argc > 1) {                         \
         int i;                               \
         found = false;                       \
         for (i = 1; i < argc; i++) {         \
            if (0 == strcmp (argv[i], #fn)) { \
               found = true;                  \
            }                                 \
         }                                    \
      }                                       \
      if (!found) {                           \
         break;                               \
      }                                       \
      printf ("running test: %s\n", #fn);     \
      fn ();                                  \
      printf ("done running: %s\n", #fn);     \
   } while (0);


int
main (int argc, char **argv)
{
   printf ("Test runner.\n");
   printf ("Pass a list of test names to run only specific tests. E.g.:\n");
   printf ("test-mongocrypt _mongocrypt_test_mcgrew\n\n");
   ADD_TEST (_test_roundtrip);
   ADD_TEST (_test_mcgrew);
   ADD_TEST (_test_log);
   ADD_TEST (_test_random_generator);
   ADD_TEST (_test_decryptor);
   ADD_TEST (_test_encryptor);

}
