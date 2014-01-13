\name{verifyPassword}
\alias{verifyPassword}
\title{Verify a hashed password}
\usage{
verifyPassword(hash, passwd)
}
\arguments{
  \item{hash}{base64 hash to verify}

  \item{passwd}{password to verify}
}
\value{
TRUE if password matches hash, otherwise FALSE
}
\description{
Verify a hashed password
}
\examples{
# Hash password using default parameters
hashed <- hashPassword("password")

# verify invalid password
verifyPassword(hashed, "bad password");

# verify correct password
verifyPassword(hashed, "password")

}
\seealso{
{ \code{\link{hashPassword}} }
}

