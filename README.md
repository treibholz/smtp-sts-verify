# smtp-sts-verify
Implementation of SMTP-STS for exim4.

SMTP-STS is currently a draft: https://tools.ietf.org/html/draft-margolis-smtp-sts-00

This is an an implementation for SMTP-STS, based on exim4 (4.86.2) on Debian Jessie with Backports.

This is heavy WiP.

## Exim-Config

### Macros

add these macros to your exim configuration:

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

### Transport

add this to your remote_smtp transport:

    tls_try_verify_hosts = *
    tls_verify_certificates = /etc/ssl/certs/ca-certificates.crt
    tls_verify_hosts = ${if eq {DOMAIN_IS_CACHED_STS_TRUE}{True}{*}{}}

    headers_add = "X-smtp-sts-verify: SMTP_STS_DOMAIN_VERIFY"
    headers_add = "X-smtp-sts-cached-enforced: DOMAIN_IS_CACHED_STS_TRUE"
    headers_add = "X-smtp-sts-MX-cipher: $tls_out_cipher"
    headers_add = "X-smtp-sts-MX-cert-sha256: ${sha256:$tls_out_peercert}"
    headers_add = "X-smtp-sts-MX-cert: ${if eq {$tls_out_certificate_verified}{1}{OK: ${certextract{issuer}{$tls_out_peercert}{$value}{none}}}{no}}"

