#include <Rcpp.h>
#include <fcntl.h>

#ifdef __MINGW32__
#include <windows.h>
#endif

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
 * This function is derived from Colin Percival's scrypt reference code
 */
static int getsalt(uint8_t salt[32]) {

    uint8_t *buf = salt;
    size_t buflen = 32;

#ifdef __MINGW32__

    HCRYPTPROV hCryptCtx;

    if (CryptAcquireContext(&hCryptCtx, NULL, NULL, PROV_RSA_FULL, 0)) {
        if (!CryptGenRandom(hCryptCtx, buflen, buf))
            goto err;
        CryptReleaseContext(hCryptCtx, 0);
    } else {
        goto err;
    }

#else

    int fd;
    ssize_t lenread;

    /* Open /dev/urandom */
    if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
        goto err;

    /* Read bytes until we have filled the buffer */
    while (buflen > 0) {
        if ((lenread = read(fd, buf, buflen)) == -1)
            goto close;

        /* The random device should never EOF */
        if (lenread == 0)
            goto close;

        /* We're partly done */
        buf += lenread;
        buflen -= lenread;
    }

    /* Close the device */
    while (close(fd) == -1) {
        if (errno != EINTR)
            goto err;
    }

    /* Success! */
    return (0);

close:
    close(fd);

#endif

err:
    /* Failure! */
    return (4);
}

// [[Rcpp::export]]
RawVector Encrypt(RawVector input, CharacterVector passwd, size_t maxmem = 0, double maxmemfrac = 0.1, double maxtime = 1.0) {
    RawVector out;
    return out;
}

// [[Rcpp::export]]
RawVector Decrypt(RawVector input, CharacterVector passwd) {
    RawVector out;
    return out;
}

// [[Rcpp::export]]
CharacterVector HashPassword(CharacterVector passwd, size_t maxmem = 0, double maxmemfrac = 0.1, double maxtime = 1.0) {

    uint8_t outbuf[96];
    int logN=0;
    uint64_t N=0;
    uint32_t r=0;
    uint32_t p=0;
    uint8_t salt[32];
    uint8_t key[64];
    uint8_t *key_hmac = &key[32];
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

    /* calculate N */
    N = (uint64_t) 1 << logN;

    /* Generate the derived key */
    std::string data = as<std::string>(passwd);
    N = (uint64_t) 1 << logN;
    if (crypto_scrypt((const uint8_t*)data.c_str(), (size_t)data.length(), salt, 32, N, r, p, key, 64)) {
        Rcerr << "Error hashing password: scrypt error." << std::endl;
        return false;
    }

    /* Construct the hash */
    memcpy(outbuf, "scrypt", 6);
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
bool VerifyPassword(CharacterVector hash, CharacterVector passwd) {

    uint8_t inbuf[96];
    int logN=0;
    uint64_t N=0;
    uint32_t r=0;
    uint32_t p=0;
    uint8_t salt[32];
    uint8_t key[64];
    uint8_t * key_hmac = &key[32];
    uint8_t tmp[32];
    SHA256_CTX sha;
    HMAC_SHA256_CTX hmac;

    /* base64 decode hash */
    std::string h = as<std::string>(hash);
    std::string b = b64decode(h.begin(), h.end());
    if (b.length() < 96) {
        Rcerr << "Error verifying password: hash too short." << std::endl;
        return false;
    }
    std::copy(b.begin(), b.end(), inbuf);

    /* Parse N, r, p, salt */
    N = (uint64_t)1 << inbuf[7];
    r = be32dec(&inbuf[8]);
    p = be32dec(&inbuf[12]);
    memcpy(salt, &inbuf[16], 32);

    /* Verify header checksum */
    SHA256_Init(&sha);
    SHA256_Update(&sha, inbuf, 48);
    SHA256_Final(tmp, &sha);
    if (memcmp(&inbuf[48], tmp, 16)) {
        Rcerr << "Error verifying password: checksum mismatch." << std::endl;
        return false;
    }

    /* Compute Derived Key */
    std::string data = as<std::string>(passwd);
    if (crypto_scrypt((const uint8_t*)data.c_str(), (size_t)data.length(), salt, 32, N, r, p, key, 64)) {
        Rcerr << "Error verifying password: scrypt error." << std::endl;
        return false;
    }

    /* Check signature (i.e., verify password). */
    HMAC_SHA256_Init(&hmac, key_hmac, 32);
    HMAC_SHA256_Update(&hmac, inbuf, 64);
    HMAC_SHA256_Final(tmp, &hmac);
    if (memcmp(tmp, &inbuf[64], 32))
        return false;

    return true; // Success
}
