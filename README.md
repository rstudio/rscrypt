# rscrypt

rscrypt is an R package for a collection of scrypt cryptographic functions. Scrypt is a
password-based key derivation function created by Colin Percival. The algorithm was specifically
designed to make it costly to perform large-scale custom hardware attacks by requiring large
amounts of memory.

## Installation

To install directly from GitHub, run this:

```
if (!require("devtools"))
    install.packages("devtools")
devtools::install_github("kippandrew/rscrypt")
```

## Usage

Hash a password:
```
hashed <- scrypt::HashPassword("good password")
```

Verify a hashed password:

```
scrypt::VerifyPassword(hashed, "bad bassword")
[1] FALSE

scrypt::VerifyPassword(hashed, "good password")
[1] TRUE
```

## Password Hashing
