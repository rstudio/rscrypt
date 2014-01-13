\name{hashPassword}
\alias{hashPassword}
\title{Hash a password}
\usage{
hashPassword(passwd, maxmem = 0.1, maxtime = 1)
}
\arguments{
  \item{passwd}{password to hash}

  \item{maxmemc}{max memory percent (default 0.1)}

  \item{maxtime}{max cpu time (default 1.0)}
}
\value{
base64 encoded hash
}
\description{
Hash a password
}
\examples{
# Hash password using default parameters
hashPassword('passw0rd')

# Hash password with custom parameters
hashPassword('passw0rd', maxmem=.25, maxtime=5.0)
}
\seealso{
\code{\link{verifyPassword}}
}

