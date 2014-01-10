\name{VerifyPassword}
\alias{VerifyPassword}
\title{Verify a hashed password}
\usage{
VerifyPassword(hash, passwd)
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
\dontrun{

# Hash password using default parameters
hashed <- HashPassword('password')

VerifyPassword(hashed, "bad password");
FALSE

VerifyPassword(hashed, "password")
TRUE

}
}
\seealso{
{ \code{\link{HashPassword}} }
}

