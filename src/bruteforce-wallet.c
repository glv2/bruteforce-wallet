/*
Bruteforce a wallet file.

Copyright 2014 Guillaume LE VAILLANT

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <db.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptic-curve.h"
#include "version.h"


unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *charset = NULL;
unsigned int charset_len = 62, min_len = 1, max_len = 8;
unsigned char *pubkey, *encrypted_seckey, *encrypted_masterkey, salt[8];
unsigned int pubkey_len, encrypted_seckey_len, encrypted_masterkey_len, method, rounds;
const EVP_CIPHER *cipher;
const EVP_MD *digest;
pthread_mutex_t found_password_lock;
char stop = 0, only_one_password = 0;


/*
 * Decryption
 */

void sha256(unsigned char *data, unsigned int len, unsigned char *hash)
{
  unsigned int size;
  EVP_MD_CTX ctx;

  EVP_DigestInit(&ctx, EVP_sha256());
  EVP_DigestUpdate(&ctx, data, len);
  EVP_DigestFinal(&ctx, hash, &size);
  EVP_MD_CTX_cleanup(&ctx);
}

void sha256d(unsigned char *data, unsigned int len, unsigned char *hash)
{
  unsigned char hash1[32];
  EVP_MD_CTX ctx;

  sha256(data, len, hash1);
  sha256(hash1, 32, hash);
}

int valid_seckey(unsigned char *seckey, unsigned int seckey_len, unsigned char *pubkey, unsigned int pubkey_len)
{
  int ret;

  if(seckey_len != 32)
    return(0);

  ret = check_eckey(seckey, pubkey, pubkey_len);

  return(ret);
}

void * decryption_func(void *arg)
{
  unsigned char prefix, *password, *key, *iv, *masterkey, *seckey, hash[32];
  unsigned int index_start, index_end, prefix_len, len, i, j, k;
  unsigned int masterkey_len1, masterkey_len2, seckey_len1, seckey_len2;
  int ret;
  unsigned int *tab;
  EVP_CIPHER_CTX ctx;

  index_start = ((unsigned int *) arg)[0];
  index_end = ((unsigned int *) arg)[1];
  prefix_len = 1;
  sha256d(pubkey, pubkey_len, hash);
  key = (unsigned char *) malloc(EVP_CIPHER_key_length(cipher));
  iv = (unsigned char *) malloc(EVP_CIPHER_iv_length(cipher));
  masterkey = (unsigned char *) malloc(encrypted_masterkey_len + EVP_CIPHER_block_size(cipher));
  seckey = (unsigned char *) malloc(encrypted_seckey_len + EVP_CIPHER_block_size(cipher));
  if((key == NULL) || (iv == NULL) || (masterkey == NULL) || (seckey == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }

  for(len = (min_len < prefix_len) ? 0 : min_len - prefix_len; len <= max_len - prefix_len; len++)
    {
      for(k = index_start; k <= index_end; k++)
        {
          prefix = charset[k];

          password = (unsigned char *) malloc(prefix_len + len + 1);
          tab = (unsigned int *) malloc((len + 1) * sizeof(unsigned int));
          if((password == NULL) || (tab == NULL))
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }
          password[0] = prefix;

          for(i = 0; i <= len; i++)
            tab[i] = 0;
          while((tab[len] == 0) && (stop == 0))
            {
              for(i = 0; i < len; i++)
                password[prefix_len + i] = charset[tab[len - 1 - i]];
              password[prefix_len + len] = '\0';

              /* Decrypt the master key with the password. */
              EVP_BytesToKey(cipher, digest, salt, password, prefix_len + len, rounds, key, iv);
              EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
              EVP_DecryptUpdate(&ctx, masterkey, &masterkey_len1, encrypted_masterkey, encrypted_masterkey_len);
              ret = EVP_DecryptFinal(&ctx, masterkey + masterkey_len1, &masterkey_len2);
              if(ret == 1)
                {
                  /* Decrypt the secret key with the master key. */
                  EVP_CIPHER_CTX_cleanup(&ctx);
                  EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), masterkey, hash);
                  EVP_DecryptUpdate(&ctx, seckey, &seckey_len1, encrypted_seckey, encrypted_seckey_len);
                  ret = EVP_DecryptFinal(&ctx, seckey + seckey_len1, &seckey_len2);
                  if((ret == 1) && valid_seckey(seckey, seckey_len1 + seckey_len2, pubkey, pubkey_len))
                    {
                      pthread_mutex_lock(&found_password_lock);
                      printf("Password candidate: %s\n", password);
                      if(only_one_password)
                        stop = 1;
                      pthread_mutex_unlock(&found_password_lock);
                    }
                }
              EVP_CIPHER_CTX_cleanup(&ctx);

              if(len == 0)
                break;
              tab[0]++;
              if(tab[0] == charset_len)
                tab[0] = 0;
              j = 0;
              while((j < len) && (tab[j] == 0))
                {
                  j++;
                  tab[j]++;
                  if(tab[j] == charset_len)
                    tab[j] = 0;
                }
            }
          free(tab);
          free(password);
        }
    }

  free(masterkey);
  free(seckey);
  free(iv);
  free(key);

  pthread_exit(NULL);
}


/*
 * Database
 */

int get_wallet_info(char *filename)
{
  DB *db;
  DBC *db_cursor;
  DBT db_key, db_data;
  int ret, mkey = 0, ckey = 0;

  /* Open the BerkeleyDB database file. */
  ret = db_create(&db, NULL, 0);
  if(ret != 0)
    {
      fprintf(stderr, "Error: db_create: %s.\n\n", db_strerror(ret));
      exit(EXIT_FAILURE);
    }

  ret = db->open(db, NULL, filename, "main", DB_UNKNOWN, DB_RDONLY, 0);
  if(ret != 0)
    {
      db->err(db, ret, "Error: %s.\n\n", filename);
      db->close(db, 0);
      exit(EXIT_FAILURE);
    }

  ret = db->cursor(db, NULL, &db_cursor, 0);
  if(ret != 0)
    {
      db->err(db, ret, "Error: %s.\n\n", filename);
      db->close(db, 0);
      exit(EXIT_FAILURE);
    }

  memset(&db_key, 0, sizeof(db_key));
  memset(&db_data, 0, sizeof(db_data));
  while((ret = db_cursor->get(db_cursor, &db_key, &db_data, DB_NEXT)) == 0)
    {
      /* Find the encrypted master key. */
      if(!mkey && (db_key.size > 7) && (memcmp(db_key.data + 1, "mkey", 4) == 0))
        {
          mkey = 1;
          encrypted_masterkey_len = ((unsigned char *) db_data.data)[0];
          encrypted_masterkey = (unsigned char *) malloc(encrypted_masterkey_len);
          if(encrypted_masterkey == NULL)
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }

          memcpy(encrypted_masterkey, db_data.data + 1, encrypted_masterkey_len);
          memcpy(salt, db_data.data + 1 + encrypted_masterkey_len + 1, 8);
          method = *((unsigned int *) (db_data.data + 1 + encrypted_masterkey_len + 1 + 8));
          rounds = *((unsigned int *) (db_data.data + 1 + encrypted_masterkey_len + 1 + 8 + 4));
        }

      /* Find an encrypted secret key. */
      if(!ckey && (db_key.size > 7) && (memcmp(db_key.data + 1, "ckey", 4) == 0))
        {
          ckey = 1;
          pubkey_len = ((unsigned char *) db_key.data)[5];
          pubkey = (unsigned char *) malloc(pubkey_len);
          encrypted_seckey_len = ((unsigned char *) db_data.data)[0];
          encrypted_seckey = (unsigned char *) malloc(encrypted_seckey_len);
          if((pubkey == NULL) || (encrypted_seckey == NULL))
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }

          memcpy(pubkey, db_key.data + 6, pubkey_len);
          memcpy(encrypted_seckey, db_data.data + 1, encrypted_seckey_len);
        }

      if(mkey && ckey)
        {
          if(method == 0)
            {
              cipher = EVP_aes_256_cbc();
              digest = EVP_sha512();
            }
          else
            {
              fprintf(stderr, "Error: encryption method not supported: %u.\n\n", method);
              exit(EXIT_FAILURE);
            }

          db_cursor->close(db_cursor);
          db->close(db, 0);
          return(1);
        }
    }

  db_cursor->close(db_cursor);
  db->close(db, 0);
  return(0);
}


/*
 * Main
 */

void usage(char *progname)
{
  fprintf(stderr, "\nbruteforce-wallet %s\n\n", VERSION);
  fprintf(stderr, "Usage: %s [options] <filename>\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -1           Stop the program after finding the first password candidate.\n");
  fprintf(stderr, "  -h           Show help and quit.\n");
  fprintf(stderr, "  -l <length>  Minimum password length.\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "  -m <length>  Maximum password length.\n");
  fprintf(stderr, "                 default: 8\n");
  fprintf(stderr, "  -s <string>  Password character set.\n");
  fprintf(stderr, "                 default: \"0123456789ABCDEFGHIJKLMNOPQRSTU\n");
  fprintf(stderr, "                           VWXYZabcdefghijklmnopqrstuvwxyz\"\n");
  fprintf(stderr, "  -t <n>       Number of threads to use.\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
  unsigned int nb_threads = 1;
  pthread_t *decryption_threads;
  char *filename;
  unsigned int **indexes;
  int i, ret, c;

  OpenSSL_add_all_algorithms();

  /* Get options and parameters. */
  opterr = 0;
  while((c = getopt(argc, argv, "1hl:m:s:t:")) != -1)
    switch(c)
      {
      case '1':
        only_one_password = 1;
        break;

      case 'h':
        usage(argv[0]);
        exit(EXIT_FAILURE);
        break;

      case 'l':
        min_len = (unsigned int) atoi(optarg);
        if(min_len == 0)
          min_len = 1;
        break;

      case 'm':
        max_len = (unsigned int) atoi(optarg);
        break;

      case 's':
        charset = optarg;
        break;

      case 't':
        nb_threads = (unsigned int) atoi(optarg);
        if(nb_threads == 0)
          nb_threads = 1;
        break;

      default:
        usage(argv[0]);
        if((optopt == 'l') || (optopt == 'm') || (optopt == 's') || (optopt == 't'))
          fprintf(stderr, "Error: missing argument for option: '-%c'.\n\n", optopt);
        else
          fprintf(stderr, "Error: unknown option: '%c'.\n\n", optopt);
        exit(EXIT_FAILURE);
        break;
      }

  if(optind >= argc)
    {
      usage(argv[0]);
      fprintf(stderr, "Error: missing filename.\n\n");
      exit(EXIT_FAILURE);
    }

  filename = argv[optind];

  if(charset == NULL)
    charset = default_charset;
  charset_len = strlen(charset);
  if(charset_len == 0)
    {
      fprintf(stderr, "Error: charset must have at least one character.\n\n");
      exit(EXIT_FAILURE);
    }
  if(nb_threads > charset_len)
    {
      fprintf(stderr, "Warning: number of threads (%u) bigger than character set length (%u). Only using %u threads.\n\n", nb_threads, charset_len, charset_len);
      nb_threads = charset_len;
    }
  if(max_len < min_len)
    max_len = min_len;

  ret = get_wallet_info(filename);
  if(ret == 0)
    {
      fprintf(stderr, "Error: couldn't find required info in wallet.\n\n");
      exit(EXIT_FAILURE);
    }

  pthread_mutex_init(&found_password_lock, NULL);

  /* Start decryption threads. */
  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  indexes = (unsigned int **) malloc(nb_threads * sizeof(unsigned int *));
  if((decryption_threads == NULL) || (indexes == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < nb_threads; i++)
    {
      indexes[i] = (unsigned int *) malloc(2 * sizeof(unsigned int));
      if(indexes[i] == NULL)
        {
          fprintf(stderr, "Error: memory allocation failed.\n\n");
          exit(EXIT_FAILURE);
        }
      indexes[i][0] = i * (charset_len / nb_threads);
      if(i == nb_threads - 1)
        indexes[i][1] = charset_len - 1;
      else
        indexes[i][1] = (i + 1) * (charset_len / nb_threads) - 1;
      ret = pthread_create(&decryption_threads[i], NULL, &decryption_func, indexes[i]);
      if(ret != 0)
        {
          perror("Error: decryption thread");
          exit(EXIT_FAILURE);
        }
    }

  for(i = 0; i < nb_threads; i++)
    {
      pthread_join(decryption_threads[i], NULL);
      free(indexes[i]);
    }
  free(indexes);
  free(decryption_threads);
  pthread_mutex_destroy(&found_password_lock);
  free(encrypted_masterkey);
  free(encrypted_seckey);
  free(pubkey);
  EVP_cleanup();

  exit(EXIT_SUCCESS);
}
