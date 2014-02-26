#include <Rcpp.h>

#if defined(_WIN32)
// See: http://stackoverflow.com/questions/11588765/using-rcpp-with-windows-specific-includes
#undef Realloc
#undef Free
#include <Windows.h>

#elif defined(__unix__) || defined(__unix) || defined(unix) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>

#if defined(BSD)
#include <sys/sysctl.h>
#endif

#endif

#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

extern "C" {
    #include "scrypt_platform.h"
    #include "crypto/crypto_scrypt.h"
}

#include "util.hpp"

#ifdef HAVE_CLOCK_GETTIME

static clock_t clocktouse;

static int getclockres(double *resd)
{
    struct timespec res;

    /*
     * Try clocks in order of preference until we find one which works.
     * (We assume that if clock_getres works, clock_gettime will, too.)
     * The use of if/else/if/else/if/else rather than if/elif/elif/else
     * is ugly but legal, and allows us to #ifdef things appropriately.
     */
#ifdef CLOCK_VIRTUAL
    if (clock_getres(CLOCK_VIRTUAL, &res) == 0)
        clocktouse = CLOCK_VIRTUAL;
    else
#endif
#ifdef CLOCK_MONOTONIC
    if (clock_getres(CLOCK_MONOTONIC, &res) == 0)
        clocktouse = CLOCK_MONOTONIC;
    else
#endif
    if (clock_getres(CLOCK_REALTIME, &res) == 0)
        clocktouse = CLOCK_REALTIME;
    else
        return (-1);

    /* Convert clock resolution to a double. */
    *resd = res.tv_sec + res.tv_nsec * 0.000000001;

    return (0);
}

static int getclocktime(struct timespec *ts)
{

#ifdef DEBUG
    REprintf("Using clock_gettime()\n");
#endif

    if (clock_gettime(clocktouse, ts))
        return (-1);

    return (0);
}

#else

static int getclockres(double *resd)
{

#ifdef DEBUG
    REprintf("Using gettimeofday()\n");
#endif

    *resd = 1.0 / CLOCKS_PER_SEC;

    return (0);
}

static int getclocktime(struct timespec *ts)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL))
        return (-1);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;

    return (0);
}

#endif

static int getclockdiff(struct timespec * st, double * diffd)
{
    struct timespec en;

    if (getclocktime(&en))
        return (1);
    *diffd = (en.tv_nsec - st->tv_nsec) * 0.000000001 +
        (en.tv_sec - st->tv_sec);

    return (0);
}

/*
 * Get CPU performance
 *
 * This function is derived from Colin Percival's scrypt reference code
 */
int getcpuperf(double *opps)
{
    struct timespec st;
    double resd, diffd;
    uint64_t i = 0;

    /* Get the clock resolution. */
    if (getclockres(&resd))
        return (2);

#ifdef DEBUG
    REprintf("Clock resolution is %f\n", resd);
#endif

    /* Loop until the clock ticks. */
    if (getclocktime(&st))
        return (2);
    do {
        /* Do an scrypt. */
        if (crypto_scrypt(NULL, 0, NULL, 0, 16, 1, 1, NULL, 0))
            return (3);

        /* Has the clock ticked? */
        if (getclockdiff(&st, &diffd))
            return (2);
        if (diffd > 0)
            break;
    } while (1);

    /* Could how many scryps we can do before the next tick. */
    if (getclocktime(&st))
        return (2);
    do {
        /* Do an scrypt. */
        if (crypto_scrypt(NULL, 0, NULL, 0, 128, 1, 1, NULL, 0))
            return (3);

        /* We invoked the salsa20/8 core 512 times. */
        i += 512;

        /* Check if we have looped for long enough. */
        if (getclockdiff(&st, &diffd))
            return (2);
        if (diffd > resd)
            break;
    } while (1);

#ifdef DEBUG
    REprintf("%ju salsa20/8 cores performed in %f seconds\n", 
        (uintmax_t)i, diffd);
#endif

    /* We can do approximately i salsa20/8 cores per diffd seconds. */
    *opps = i / diffd;
    return (0);
}

/*
 * Get available memory
 *
 * This function is derived from:
 * http://nadeausoftware.com/articles/2012/09/c_c_tip_how_get_physical_memory_size_system
 */
int getmemlimit(size_t *memlimit) {

#if defined(_WIN32) && (defined(__CYGWIN__) || defined(__CYGWIN32__) || defined(__MINGW__) || defined(__MINGW32__) )
    /* Cygwin under Windows. ------------------------------------ */
    /* New 64-bit MEMORYSTATUSEX isn't available.  Use old 32.bit */
    MEMORYSTATUS status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatus( &status );
    *memlimit = (size_t)status.dwTotalPhys;
    return 0;

#elif defined(_WIN32)
    /* Windows. ------------------------------------------------- */
    /* Use new 64-bit MEMORYSTATUSEX, not old 32-bit MEMORYSTATUS */
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx( &status );
    *memlimit = (size_t)status.ullTotalPhys;
    return 0;

#elif defined(__unix__) || defined(__unix) || defined(unix) || (defined(__APPLE__) && defined(__MACH__))
    /* UNIX variants. ------------------------------------------- */

    struct rlimit rl;
    size_t memrlimit;

    /* Find the least of... */
    memrlimit = (size_t)(-1);

    /* ... RLIMIT_AS... */
#ifdef RLIMIT_AS
    REprintf("Checking RLIMIT_AS\n");
    if (getrlimit(RLIMIT_AS, &rl))
        return -1;
    if ((rl.rlim_cur != RLIM_INFINITY) && ((size_t)rl.rlim_cur < memrlimit)) {
        memrlimit = rl.rlim_cur;
        REprintf("RLIMIT_AS = %llu\n", memrlimit);
    }
#endif

#ifdef RLIMIT_DATA 
    /* ... RLIMIT_DATA... */
    if (getrlimit(RLIMIT_DATA, &rl))
        return -1;
    REprintf("Checking RLIMIT_DATA\n");
    if ((rl.rlim_cur != RLIM_INFINITY) && ((size_t)rl.rlim_cur < memrlimit)) {
        memrlimit = (size_t)rl.rlim_cur;
        REprintf("RLIMIT_DATA = %llu\n", memrlimit);
    }
#endif

    /* ... RLIMIT_RSS. */
#ifdef RLIMIT_RSS
    REprintf("Checking RLIMIT_RSS\n");

    if (getrlimit(RLIMIT_RSS, &rl))
        return -1;
    if ((rl.rlim_cur != RLIM_INFINITY) && ((size_t)rl.rlim_cur < memrlimit)) {
        memrlimit = rl.rlim_cur;
        REprintf("RLIMIT_RSS = %llu\n", memrlimit);
    }
#endif

    REprintf("memrlimit=%llu\n", memrlimit);

    if (memrlimit < (size_t)(-1)) {
        *memlimit = memrlimit;
        return 0;
    }

#if defined(CTL_HW) && (defined(HW_MEMSIZE) || defined(HW_PHYSMEM64))
    int mib[2];
    mib[0] = CTL_HW;
#if defined(HW_MEMSIZE)
    mib[1] = HW_MEMSIZE;    // OSX
#elif defined(HW_PHYSMEM64)
    mib[1] = HW_PHYSMEM64;  // NetBSD, OpenBSD
#endif
    int64_t size = 0;       // 64-bit
    size_t len = sizeof( size );
    if ( sysctl( mib, 2, &size, &len, NULL, 0 ) == 0 ) {
        *memlimit = (size_t)size;
        return 0;
    }
    return -1; // Failure

#elif defined(_SC_AIX_REALMEM)
    /* AIX. ----------------------------------------------------- */
    *memlimit = (size_t)sysconf( _SC_AIX_REALMEM ) * (size_t)1024L;
    return 0;

#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
    /* FreeBSD, Linux, OpenBSD, and Solaris. -------------------- */
    *memlimit = (size_t)sysconf( _SC_PHYS_PAGES ) * (size_t)sysconf( _SC_PAGESIZE );
    return 0;

#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGE_SIZE)
    /* Legacy. -------------------------------------------------- */
    *memlimit = (size_t)sysconf( _SC_PHYS_PAGES ) * (size_t)sysconf( _SC_PAGE_SIZE );
    return 0;

#elif defined(CTL_HW) && (defined(HW_PHYSMEM) || defined(HW_REALMEM))
    /* DragonFly BSD, FreeBSD, NetBSD, OpenBSD, and OSX. -------- */
    int mib[2];
    mib[0] = CTL_HW;
#if defined(HW_REALMEM)
    mib[1] = HW_REALMEM;        // FreeBSD
#elif defined(HW_PYSMEM)
    mib[1] = HW_PHYSMEM;        // Others
#endif
    unsigned int size = 0;      // 32-bit
    size_t len = sizeof( size );
    if ( sysctl( mib, 2, &size, &len, NULL, 0 ) == 0 ) {
        *memlimit = (size_t)size;
        return 0;
    }
    return -1; // Failure
#endif

#else
    return -2; // Unknown OS
#endif

}

/*
 * Obtains salt for password hash.
 * This function is derived from Colin Percival's scrypt reference code
 */
int getsalt(uint8_t salt[32]) {

    uint8_t *buf = salt;
    size_t buflen = 32;

#if defined(_WIN32)

    HCRYPTPROV hCryptCtx;

    if (CryptAcquireContext(&hCryptCtx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (!CryptGenRandom(hCryptCtx, buflen, buf))
            goto err;
        CryptReleaseContext(hCryptCtx, 0);
    } else {
        goto err;
    }
    
    /* Success! */
    return (0);
    
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

