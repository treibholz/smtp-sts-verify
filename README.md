# smtp-sts-verify
Implementation of SMTP-STS for exim4.

SMTP-STS is currently a draft: https://tools.ietf.org/html/draft-margolis-smtp-sts-00

This is an an implementation for SMTP-STS, based on exim4 (4.86.2) on Debian Jessie with Backports.

This is heavy WiP.

## Usage:

Copy verify.py to /usr/local/bin/.

    usage: verify.py [-h] -d D -s TXT -m MX [-c FILE] [-D] [-v]

    Verify SMTP-STS

    optional arguments:
      -h, --help            show this help message and exit
      -d D, --domain D      domain to test (default: None)
      -s TXT, --smtp-sts TXT
                            _smtp-sts TXT record (default: None)
      -m MX, --mx MX        MXes (default: None)
      -c FILE, --cachedb FILE
                            sqlite3 cachedb (default: /var/tmp/smtp-sts-cache.db)
      -D, --dnssec          DNSSEC was used used (default: False)
      -v, --verbose         verbose output (default: False)


## Exim Configuration

### Macros

add these macros to your exim configuration:

```
SMTP_STS_DOMAIN_TXT = ${lookup dnsdb{>: dnssec_lax,txt=_smtp-sts.$domain} \
                            {$value}\
                            {0}\
                        }

SMTP_STS_DOMAIN_VERIFY = ${run{\
                            /usr/local/bin/verify.py \
                                -d $domain \
                                -s \"SMTP_STS_DOMAIN_TXT\" \
                                -m $host \
                            }{GOOD: $value}{BAD: $value}\
                        }

DOMAIN_IS_CACHED_STS_TRUE = ${lookup sqlite {/var/tmp/smtp-sts-cache.db \
                                select tls_only from sts_cache where \
                                    domain = '${quote_sqlite:$domain}' and \
                                    expires > strftime('%s','now')}\
                            }
```

### Transport

add this to your remote_smtp transport:

```INI
# Try to use TLS everywhere
tls_try_verify_hosts = *
# This is your local CA store
tls_verify_certificates = /etc/ssl/certs/ca-certificates.crt
# if a domain is known to work with TLS, has an STS-TXT-Record and set to=true,
# always enforce TLS verification.
tls_verify_hosts = ${if eq {DOMAIN_IS_CACHED_STS_TRUE}{True}{*}{}}

# call external verify-script
headers_add = "X-smtp-sts-verify: SMTP_STS_DOMAIN_VERIFY"
# Add some headers with infos (optional)
headers_add = "X-smtp-sts-cached-enforced: DOMAIN_IS_CACHED_STS_TRUE"
headers_add = "X-smtp-sts-MX-cipher: $tls_out_cipher"
headers_add = "X-smtp-sts-MX-cert-sha256: ${sha256:$tls_out_peercert}"
headers_add = "X-smtp-sts-MX-cert: ${if eq {$tls_out_certificate_verified}{1}{OK: ${certextract{issuer}{$tls_out_peercert}{$value}{none}}}{no}}"
```
