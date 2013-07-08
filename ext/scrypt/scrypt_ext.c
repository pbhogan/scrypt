#include "scrypt_ext.h"
#include "scrypt_calibrate.h"
#include "crypto_scrypt.h"


typedef struct {
  uint64_t n;
  uint32_t r;
  uint32_t p;
  uint64_t size;
} Calibration;


RBFFI_EXPORT int sc_calibrate(double maxmemfrac, double maxtime, void *out)
{
    Calibration *result = (Calibration *) out;
              // result->size == maxmem
    return calibrate(result->size, maxmemfrac, maxtime, &result->n, &result->r, &result->p);    // 0 == success
}


RBFFI_EXPORT int sc_crypt(const char *safe_key, const char *safe_salt, void *buffer, void *in)
{
    Calibration *settings = (Calibration *) in;
    return crypto_scrypt(
        (uint8_t *) safe_key, strlen(safe_key),
        (uint8_t *) safe_salt, strlen(safe_salt),
        settings->n, settings->r, settings->p,
        (uint8_t *) buffer, settings->size
    );  // 0 == success
}
