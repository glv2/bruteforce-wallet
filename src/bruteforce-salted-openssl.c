/*
Bruteforce a file encrypted (with salt) by openssl.

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
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *charset = NULL, *data = NULL, salt[8];
unsigned int charset_len = 62, data_len = 0, min_len = 1, max_len = 8;
const EVP_CIPHER *cipher = NULL;
const EVP_MD *digest = NULL;
pthread_mutex_t found_password_lock;
char stop = 0, only_one_password = 0;


/*
 * Decryption
 */

int valid_data(unsigned char *data, unsigned int len)
{
  unsigned int i;
  unsigned char c;
  unsigned int bad = 0;

  /* Count the number of not printable characters */
  for(i = 0; i < len; i++)
    {
      c = data[i];
      if(!isprint(c))
        bad++;
    }

  /* Consider the decrypted data as invalid if there is more than 10% of not printable characters */
  if(bad > len / 10)
    return(0);
  else
    return(1);
}

void * decryption_func(void *arg)
{
  unsigned char prefix, *password, *key, *iv, *out;
  unsigned int index_start, index_end, prefix_len, len, out_len1, out_len2, i, j, k;
  int ret;
  unsigned int *tab;
  EVP_CIPHER_CTX ctx;

  index_start = ((unsigned int *) arg)[0];
  index_end = ((unsigned int *) arg)[1];
  prefix_len = 1;
  key = (unsigned char *) malloc(EVP_CIPHER_key_length(cipher));
  iv = (unsigned char *) malloc(EVP_CIPHER_iv_length(cipher));
  out = (unsigned char *) malloc(data_len + EVP_CIPHER_block_size(cipher));
  if((key == NULL) || (iv == NULL) || (out == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n");
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
              fprintf(stderr, "Error: memory allocation failed.\n");
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
              /* Decrypt data with password */
              EVP_BytesToKey(cipher, digest, salt, password, prefix_len + len, 1, key, iv);
              EVP_DecryptInit(&ctx, cipher, key, iv);
              EVP_DecryptUpdate(&ctx, out, &out_len1, data, data_len);
              ret = EVP_DecryptFinal(&ctx, out + out_len1, &out_len2);
              if((ret == 1) && valid_data(out, out_len1 + out_len2))
                {
                  pthread_mutex_lock(&found_password_lock);
                  printf("Password candidate: %s\n", password);
                  if(only_one_password)
                    stop = 1;
                  pthread_mutex_unlock(&found_password_lock);
                }
              EVP_CIPHER_CTX_cleanup(&ctx);

              tab[0]++;
              if(tab[0] == charset_len)
                tab[0] = 0;
              j = 0;
              while(tab[j] == 0)
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

  free(out);
  free(iv);
  free(key);

  pthread_exit(NULL);
}


/*
 * Main
 */

void list_ciphers(const EVP_CIPHER *c, const char *from, const char *to, void *arg)
{
  static char *last = NULL;
  char *current;

  if(c)
    {
      current = (char *) EVP_CIPHER_name(c);
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, current) >= 0)
        return;
      else
        last = current;
      fprintf(stderr, "  %s\n", current);
    }
  else if(from && to)
    {
      current = (char *) from;
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, from) >= 0)
        return;
      else
        last = (char *) from;
      fprintf(stderr, "  %s => %s\n", from, to);
    }
}

void list_digests(const EVP_MD *d, const char *from, const char *to, void *arg)
{
  static char *last = NULL;
  char *current;

  if(d)
    {
      current = (char *) EVP_MD_name(d);
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, current) >= 0)
        return;
      else
        last = current;
      fprintf(stderr, "  %s\n", current);
    }
  else if(from && to)
    {
      current = (char *) from;
      if(last == NULL)
        last = current;
      else if(strcasecmp(last, from) >= 0)
        return;
      else
        last = (char *) from;
      fprintf(stderr, "  %s => %s\n", from, to);
    }
}

void usage(char *progname)
{
  fprintf(stderr, "Usage: %s [options] <filename>\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -1           Stop the program after finding the first password candidate.\n");
  fprintf(stderr, "  -a           List the available cipher and digest algorithms.\n");
  fprintf(stderr, "  -c <cipher>  Cipher for decryption.\n");
  fprintf(stderr, "                 default: aes-256-cbc\n");
  fprintf(stderr, "  -d <digest>  Digest for key and initialization vector generation.\n");
  fprintf(stderr, "                 default: md5\n");
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

void list_algorithms(void)
{
  fprintf(stderr, "Available ciphers:\n");
  EVP_CIPHER_do_all_sorted(list_ciphers, NULL);
  fprintf(stderr, "\nAvailable digests:\n");
  EVP_MD_do_all_sorted(list_digests, NULL);
  fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
  unsigned int nb_threads = 1;
  pthread_t *decryption_threads;
  char *filename;
  unsigned int **indexes;
  int fd, i, ret, c;
  struct stat file_stats;

  OpenSSL_add_all_algorithms();

  /* Get options and parameters */
  opterr = 0;
  while((c = getopt(argc, argv, "1ac:d:hl:m:s:t:")) != -1)
    switch(c)
      {
      case '1':
        only_one_password = 1;
        break;

      case 'a':
        list_algorithms();
        exit(EXIT_FAILURE);
        break;

      case 'c':
        cipher = EVP_get_cipherbyname(optarg);
        if(cipher == NULL)
          {
            fprintf(stderr, "Error: unknown cipher: %s.\n", optarg);
            exit(EXIT_FAILURE);
          }
        break;

      case 'd':
        digest = EVP_get_digestbyname(optarg);
        if(digest == NULL)
          {
            fprintf(stderr, "Error: unknown digest: %s.\n", optarg);
            exit(EXIT_FAILURE);
          }
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
        if((optopt == 'c') || (optopt == 'd') || (optopt == 'l') || (optopt == 'm') || (optopt == 's') || (optopt == 't'))
          fprintf(stderr, "Error: missing argument for option: '-%c'.\n", optopt);
        else
          fprintf(stderr, "Error: unknown option: '%c'.\n", optopt);
        exit(EXIT_FAILURE);
        break;
      }

  if(optind >= argc)
    {
      usage(argv[0]);
      fprintf(stderr, "Error: missing filename.\n");
      exit(EXIT_FAILURE);
    }

  filename = argv[optind];

  if(cipher == NULL)
    cipher = EVP_aes_256_cbc();
  if(digest == NULL)
    digest = EVP_md5();
  if(charset == NULL)
    charset = default_charset;
  charset_len = strlen(charset);
  if(charset_len == 0)
    {
      fprintf(stderr, "Error: charset must have at least one character.\n");
      exit(EXIT_FAILURE);
    }
  if(max_len < min_len)
    max_len = min_len;

  /* Check header */
  fd = open(filename, O_RDONLY);
  if(fd == -1)
    {
      perror("open file");
      exit(EXIT_FAILURE);
    }
  memset(salt, 0, sizeof(salt));
  ret = read(fd, salt, 8);
  if(strncmp(salt, "Salted__", 8) != 0)
    {
      close(fd);
      fprintf(stderr, "Error: %s is not a salted openssl file.\n", filename);
      exit(EXIT_FAILURE);
    }

  /* Read salt */
  ret = read(fd, salt, 8);
  if(ret != 8)
    {
      close(fd);
      fprintf(stderr, "Error: could not read salt.\n");
      exit(EXIT_FAILURE);
    }

  /* Read encrypted data */
  ret = fstat(fd, &file_stats);
  data_len = file_stats.st_size - 16;
  data = (char *) malloc(data_len);
  if(data == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < data_len;)
    {
      ret = read(fd, data + i, data_len - i);
      if(ret == -1)
        {
          close(fd);
          fprintf(stderr, "Error: could not read data.\n");
          exit(EXIT_FAILURE);
        }
      else if(ret > 0)
        i += ret;
    }
  close(fd);

  pthread_mutex_init(&found_password_lock, NULL);
  
  /* Start decryption threads */
  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  indexes = (unsigned int **) malloc(nb_threads * sizeof(unsigned int *));
  if((decryption_threads == NULL) || (indexes == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < nb_threads; i++)
    {
      indexes[i] = (unsigned int *) malloc(2 * sizeof(unsigned int));
      if(indexes[i] == NULL)
        {
          fprintf(stderr, "Error: memory allocation failed.\n");
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
          perror("decryption thread");
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
  free(data);
  EVP_cleanup();

  exit(EXIT_SUCCESS);
}
