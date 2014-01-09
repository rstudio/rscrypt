\name{scrypt-package}
\alias{scrypt-package}
\alias{scrypt}
\alias{rscrypt}
\docType{package}
\title{
    scrypt key derivation function for R
}
\description{
    scrypt is an R package for working with scrypt. Scrypt is a password-based key
    derivation function created by Colin Percival. The algorithm was specifically
    designed to make it costly to perform large-scale custom hardware attacks by
    requiring large amounts of memory.
}
\details{
    \tabular{ll}{
        Package: \tab scrypt\cr
        Type: \tab Package\cr
        Version: \tab 0.1\cr
        Date: \tab 2014-01-07\cr
        License: \tab GPLv3 \cr
    }

The scrypt package can be used for hashing and verifying passwords, or encrypting and 
decrypting data. Additionally, the scrypt function can be used directly.
}
\author{
    RStudio, Inc.; Colin Percival
    Maintainer: Andy Kipp <andy@rstudio.com>
}
\references{
    \href{http://www.tarsnap.com/scrypt.html}{scrypt}
}
\keyword{ package }
\seealso{
  \code{\link{HashPassword}}, \code{\link{VerifyPassword}} and \code{\link{Crypt}}
}
