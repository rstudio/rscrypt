#include <Rcpp.h>
#include <fcntl.h>
#include "base64.hpp"

extern "C" {
  #include "util/sysendian.h"
  #include "util/memlimit.c"
  #include "crypto/crypto_scrypt.h" 
  #include "crypto/sha256.h"
  #include "scryptenc/scryptenc_cpuperf.h"
}

using namespace Rcpp;

/*
 * Given maxmem, maxmemfrac and maxtime, this functions calculates the N,r,p variables. 
 * This is copied directly from Colin Percival's srypt reference code
 */
static int getparams(size_t maxmem, double maxmemfrac, double maxtime, int * logN, uint32_t * r, uint32_t * p) {
    // Note: logN (as opposed to N) is calculated here. This is because it is compact (it can be represented by an int)
    //       and it is easy (and quick) to convert to N by right shifting bits
    size_t memlimit;
    double opps;
    double opslimit;
    double maxN, maxrp;
    int rc;

    /* Figure out how much memory to use. */
    if (memtouse(maxmem, maxmemfrac, &memlimit))
        return (1);

    /* Figure out how fast the CPU is. */
    if ((rc = scryptenc_cpuperf(&opps)) != 0)
        return (rc);
    opslimit = opps * maxtime;

    /* Allow a minimum of 2^15 salsa20/8 cores. */
    if (opslimit < 32768)
        opslimit = 32768;

    /* Fix r = 8 for now. */
    *r = 8;

    /*
    * The memory limit requires that 128Nr <= memlimit, while the CPU
    * limit requires that 4Nrp <= opslimit. If opslimit < memlimit/32,
    * opslimit imposes the stronger limit on N.
    */
    if (opslimit < memlimit/32) {
        /* Set p = 1 and choose N based on the CPU limit. */
        *p = 1;
        maxN = opslimit / (*r * 4);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
                break;
        }
    } else {
        /* Set N based on the memory limit. */
        maxN = memlimit / (*r * 128);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
            break;
        }

        /* Choose p based on the CPU limit. */
        maxrp = (opslimit / 4) / ((uint64_t)(1) << *logN);
        if (maxrp > 0x3fffffff)
            maxrp = 0x3fffffff;
        *p = (uint32_t)(maxrp) / *r;
    }

    /* Success! */
    return (0);
}

/*
 * Obtains salt for password hash. 
 * This function is copied from Colin Percival's scrypt reference code
 */
static int getsalt(uint8_t salt[32]) {
        int fd;
        ssize_t lenread;
        uint8_t * buf = salt;
        size_t buflen = 32;

        /* Open /dev/urandom. */
        if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
                goto err0;

        /* Read bytes until we have filled the buffer. */
        while (buflen > 0) {
                if ((lenread = read(fd, buf, buflen)) == -1)
                        goto err1;

                /* The random device should never EOF. */
                if (lenread == 0)
                        goto err1;

                /* We're partly done. */
                buf += lenread;
                buflen -= lenread;
        }

        /* Close the device. */
        while (close(fd) == -1) {
                if (errno != EINTR)
                        goto err0;
        }

        /* Success! */
        return (0);

err1:
        close(fd);
err0:
        /* Failure! */
        return (4);
}

// [[Rcpp::export]]
CharacterVector HashPassword(CharacterVector passwd, size_t maxmem, double maxmemfrac, double maxtime) {
  uint8_t outbuf[96];
  int logN=0;
  uint64_t N=0;
  uint32_t r=0, p=0;
  uint8_t salt[32];
  uint8_t key[64];
  uint8_t * key_hmac = &key[32];
  uint8_t tmp[32];
  SHA256_CTX sha;
  HMAC_SHA256_CTX hmac;
  int rc;

  /* Calculate logN, r, p */
  if ((rc = getparams(maxmem, maxmemfrac, maxtime, &logN, &r, &p) != 0))
    return (rc);
    
  /* Get Some Salt */
  if ((rc = getsalt(salt)) != 0)
    return (rc); 
  
  // calculate N
  N = (uint64_t) 1 << logN;

#ifdef DEBUG
  Rprintf("N=%d, r=%d, p=%d", N, r, p);
#endif

  /* Generate the derived key */
  std::string data = as<std::string>(passwd);
  N = (uint64_t) 1 << logN;
  if (crypto_scrypt((const uint8_t*)data.c_str(), (size_t)data.length(), salt, 32, N, r, p, key, 64)) {
    return (3);
  }
  
  /* Construct the hash */
  memcpy(outbuf, "scrypt", 6); // Sticking with Colin Percival's format of putting scrypt at the beginning
  outbuf[6] = 0;
  outbuf[7] = logN;
  be32enc(&outbuf[8], r);
  be32enc(&outbuf[12], p);
  memcpy(&outbuf[16], salt, 32);

  /* Add checksum */
  SHA256_Init(&sha);
  SHA256_Update(&sha, outbuf, 48);
  SHA256_Final(tmp, &sha);
  memcpy(&outbuf[48], tmp, 16);

  /* Add signature (used for verifying password) */
  HMAC_SHA256_Init(&hmac, key_hmac, 32);
  HMAC_SHA256_Update(&hmac, outbuf, 64);
  HMAC_SHA256_Final(tmp, &hmac);
  memcpy(&outbuf[64], tmp, 32);

  // return base64 encoded hash
  return b64encode(outbuf, outbuf + 96);
}

// [[Rcpp::export]]
bool VerifyPassword(RawVector hash, CharacterVector passwd) {
  return false;
}
