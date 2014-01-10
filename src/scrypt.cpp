#include <Rcpp.h>

#include "base64.hpp"
#include "util.hpp"

extern "C" {
    #include "util/sysendian.h"
    #include "crypto/sha256.h"
    #include "crypto/crypto_scrypt.h"
}

using namespace Rcpp;

/*
 * Calcualte the scrypt parameters for this platform
 *
 * This function is derived from Colin Percival's scrypt reference code
 */
static int getparams(double maxmem, double maxtime, int *logN, uint32_t *r, uint32_t *p) {
    // Note: logN (as opposed to N) is calculated here. This is because it is compact (it can be represented by an int)
    //       and it is easy (and quick) to convert to N by right shifting bits
    size_t totalmem;
    size_t memlimit;
    double opps;
    double opslimit;
    double maxN, maxrp;
    int rc;

    /* Get available memory */
    if ((rc = getmemlimit(&totalmem)) != 0) {
        return (rc);
    }

    /* Figure out how much memory to use. */
    if (maxmem > 0.5 || maxmem == 0)
        memlimit = totalmem * 0.5;
    else
        memlimit = totalmem * maxmem;

    /* Minimum amount of memory os 1Mib */
    if (memlimit < 1048576) 
        memlimit = 1048576;

#ifdef DEBUG
    REprintf("totalmem=%llu, memlimit=%llu\n", totalmem, memlimit);
#endif

    /* Figure out how fast the CPU is. */
    if ((rc = getcpuperf(&opps)) != 0)
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

//' Hash a password
//'
//' @param passwd password to hash
//' @param maxmemc max memory percent (default 0.1)
//' @param maxtime max cpu time (default 1.0)
//' @return
//' base64 encoded password hash
//' @examples
//' \dontrun{
//'
//' # Hash password using default parameters
//' HashPassword('passw0rd')
//'
//' # Hash password with custom parameters
//' HashPassword('passw0rd', 0, .25, 5.0)
//'
//' }
//' @seealso \code{\link{VerifyPassword}}
// [[Rcpp::export]]
CharacterVector HashPassword(CharacterVector passwd, double maxmem = 0.1, double maxtime = 1.0) {

    uint8_t outbuf[96];
    int logN=0;
    uint64_t n=0;
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
    if ((rc = getparams(maxmem, maxtime, &logN, &r, &p) != 0))
        return (rc);

    /* Get Some Salt */
    if ((rc = getsalt(salt)) != 0)
        return (rc); 

    /* calculate n */
    n = (uint64_t) 1 << logN;

#ifdef DEBUG
    REprintf("n=%llu, r=%d, p=%d\n", n, r, p);
#endif

    /* Generate the derived key */
    std::string data = as<std::string>(passwd);
    if (crypto_scrypt((const uint8_t*)data.c_str(), (size_t)data.length(), salt, 32, n, r, p, key, 64)) {
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

//' Verify a hashed password
//'
//' @param hash hash to verify 
//' @param passwd password to verify
//' @return
//' TRUE if password matches hash, otherwise false 
//' @examples
//' \dontrun{
//'
//' # Hash password using default parameters
//' hashed <- HashPassword('password')
//'
//' VerifyPassword(hashed, "bad password");
//' FALSE
//' 
//' VerifyPassword(hashed, "password")
//' TRUE
//' 
//' }
//' @seealso {
//' \code{\link{HashPassword}}
//' }
// [[Rcpp::export]]
bool VerifyPassword(CharacterVector hash, CharacterVector passwd) {

    uint8_t inbuf[96];
    int logN=0;
    uint64_t n=0;
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
    n = (uint64_t)1 << inbuf[7];
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
    if (crypto_scrypt((const uint8_t*)data.c_str(), (size_t)data.length(), salt, 32, n, r, p, key, 64)) {
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

// [[Rcpp::export]]
RawVector Crypt(RawVector passwd, RawVector salt, uint32_t n, uint32_t r, uint32_t p, uint32_t length = 64) {
    uint8_t outbuf[length];

    const std::vector<uint8_t> passwdbuf = as<std::vector<uint8_t> >(passwd);
    const std::vector<uint8_t> saltbuf = as<std::vector<uint8_t> >(salt);

    if (crypto_scrypt(passwdbuf.data(), passwdbuf.size(), saltbuf.data(), saltbuf.size(), (uint64_t)n, r, p, outbuf, length)) {
        stop("scrypt error");
    }
    
    RawVector out(length);
    std::copy(outbuf, outbuf + length, out.begin());
    return out;
}
