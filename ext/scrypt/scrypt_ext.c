#include "scrypt_ext.h"
#include "scrypt_calibrate.h"
#include "crypto_scrypt.h"


typedef struct {
  uint64_t n;
  uint32_t r;
  uint32_t p;
} Calibration;


RBFFI_EXPORT int sc_calibrate(size_t maxmem, double maxmemfrac, double maxtime, Calibration *result)
{
    return calibrate(maxmem, maxmemfrac, maxtime, &result->n, &result->r, &result->p);    // 0 == success
}
