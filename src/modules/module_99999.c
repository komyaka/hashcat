/* module_99999.c
 *
 * Модуль Ethereum brainwallet (m99999) — исправленная версия
 *
 * Комментарии и сообщения — на русском языке.
 *
 * Изменения:
 * - KERN_FILE_A0/A3 по умолчанию указывают на m99999_a0-pure.cl / m99999_a3-pure.cl
 * - Безопасный вызов hex_to_bytes: копируем 40 символов в локальный буфер и завершаем NUL
 * - cmp_hash использует DGST_SIZE * 4 вместо "магического" 20
 * - binary_to_hex корректно ставит '\0' даже при длине 0
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "logging.h"
#include "memory.h"
#include "event.h"
#include "thread.h"
#include "backend.h"

#include <string.h>
#include <ctype.h>
#include <stdint.h>

#ifndef KERN_FILE_A0
#define KERN_FILE_A0 "m99999_a0-pure.cl"
#endif

#ifndef KERN_FILE_A3
#define KERN_FILE_A3 "m99999_a3-pure.cl"
#endif

#ifndef DGST_SIZE
#define DGST_SIZE 5
#endif

static void addr_u8_to_u32_LE (const u8 *in, u32 *out)
{
  for (int i = 0; i < 5; i++)
  {
    const int off = i * 4;
    out[i] = (u32) in[off + 0]
           | ((u32) in[off + 1] << 8)
           | ((u32) in[off + 2] << 16)
           | ((u32) in[off + 3] << 24);
  }
}

static void addr_u32_to_u8_LE (const u32 *in, u8 *out)
{
  for (int i = 0; i < 5; i++)
  {
    const u32 v = in[i];
    const int off = i * 4;
    out[off + 0] = (u8) (v & 0xff);
    out[off + 1] = (u8) ((v >> 8) & 0xff);
    out[off + 2] = (u8) ((v >> 16) & 0xff);
    out[off + 3] = (u8) ((v >> 24) & 0xff);
  }
}

static int bytes_to_hex_lower (const u8 *bytes, int len, char *hex_output, int out_size)
{
  static const char hexmap[] = "0123456789abcdef";

  if (out_size < (len * 2)) return -1;

  for (int i = 0; i < len; i++)
  {
    const u8 b = bytes[i];
    hex_output[i * 2 + 0] = hexmap[(b >> 4) & 0xF];
    hex_output[i * 2 + 1] = hexmap[b & 0xF];
  }

  return len * 2;
}

static int parse_hash (hashcat_ctx_t *hashcat_ctx, void *digest_buf, const char *line_buf, const int line_len)
{
  (void) hashcat_ctx;

  u32 *digests_buf = ((u32 *) digest_buf) + DIGEST_M0;

  if (line_buf == NULL)
  {
    log_error ("Ошибка: NULL указатель line_buf");
    return PARSER_HASH_LENGTH;
  }

  int line_len_real = line_len;
  while (line_len_real > 0)
  {
    const char c = line_buf[line_len_real - 1];
    if ((c == '\n') || (c == '\r')) line_len_real--;
    else break;
  }

  if ((line_len_real != 40) && (line_len_real != 42))
  {
    log_error ("Ошибка: неверная длина входной строки (ожидается 40 или 42 символа)");
    return PARSER_HASH_LENGTH;
  }

  const char *hash_str = line_buf;
  int hash_len = line_len_real;

  if ((hash_len == 42) && (hash_str[0] == '0') && (hash_str[1] == 'x' || hash_str[1] == 'X'))
  {
    hash_str += 2;
    hash_len -= 2;
  }

  if (hash_len != 40)
  {
    log_error ("Ошибка: неверная длина хеша после опционального 0x (ожидается 40 символов)");
    return PARSER_HASH_LENGTH;
  }

  u8 addr[20] = { 0 };

  {
    char tmp[41];
    memcpy (tmp, hash_str, 40);
    tmp[40] = '\0';

    if (hex_to_bytes (tmp, 40, addr, NULL) == -1)
    {
      log_error ("Ошибка: недопустимые hex-символы в хеше");
      return PARSER_HASH_ENCODING;
    }
  }

  addr_u8_to_u32_LE (addr, digests_buf);

  return PARSER_OK;
}

static int cmp_hash (void *digest_buf1, void *digest_buf2)
{
  const u32 *d1 = ((const u32 *) digest_buf1) + DIGEST_M0;
  const u32 *d2 = ((const u32 *) digest_buf2) + DIGEST_M0;

  return memcmp (d1, d2, DGST_SIZE * 4);
}

static int hash_to_binary (void *digest_buf, char *line_buf, const int line_size, const int hash_encoding)
{
  (void) hash_encoding;

  if (line_buf == NULL) return 0;

  const u32 *digests_buf = ((const u32 *) digest_buf) + DIGEST_M0;

  u8 addr[20];
  addr_u32_to_u8_LE (digests_buf, addr);

  const int needed = 2 + 40;
  if (line_size < (needed + 1))
  {
    log_error ("Ошибка: буфер вывода слишком мал в hash_to_binary");
    return 0;
  }

  line_buf[0] = '0';
  line_buf[1] = 'x';

  if (bytes_to_hex_lower (addr, 20, line_buf + 2, 40) != 40)
  {
    log_error ("Ошибка: конвертация в hex в hash_to_binary завершилась неудачей");
    return 0;
  }

  line_buf[2 + 40] = '\0';

  return needed;
}

static void binary_to_hex (u8 *digest, char *hex_output, const int digest_len)
{
  if ((digest == NULL) || (hex_output == NULL) || (digest_len < 0)) return;

  int rc = bytes_to_hex_lower (digest, digest_len, hex_output, digest_len * 2);
  if (rc >= 0) hex_output[rc] = '\0';
}

static void init_kernel (hashcat_ctx_t *hashcat_ctx, const u32 algo, const u32 opti_type)
{
  (void) hashcat_ctx;
  (void) algo;
  (void) opti_type;
}

static void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_name = MODULE_NAME;
  module_ctx->short_module_desc = "Ethereum Brainwallet (SHA256 + secp256k1 + Keccak)";
  module_ctx->long_module_desc = "Cracks Ethereum addresses from brainwallets using SHA256(priv) -> secp256k1 pubkey -> Keccak256(pub[1:])[-20:]";

  module_ctx->supported_hash_types = SUPPORTED_TYPE;

  module_ctx->attack_exec = ATTACK_EXEC_INSIDE_KERNEL;

  module_ctx->kern_type = 1;
  module_ctx->dgst_size = DGST_SIZE;
  module_ctx->a0_file = KERN_FILE_A0;
  module_ctx->a3_file = KERN_FILE_A3;

  module_ctx->opti_type = OPTI_TYPE_ZERO_BYTE;

  module_ctx->parse_func = parse_hash;
  module_ctx->hash_to_binary_func = hash_to_binary;
  module_ctx->cmp_hash_func = cmp_hash;

  module_ctx->init_kernel_func = init_kernel;
}

module_register (module_99999);
