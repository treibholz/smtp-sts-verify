#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import time
import argparse
import re
import sys
import sqlite3

class StsPolicy(object): # {{{
    """docstring for StsPolicy"""
    def __init__(self, domain, sts_record, dnssec=False, cached_since=0):
        super(StsPolicy, self).__init__()

        self.v   = None
        self.a   = None
        self.c   = None
        self.e   = None
        self.to  = None
        self.rua = None
        self.mx  = None

        self.cached_since   = cached_since
        self.now            = int(time.time())
        self.domain         = domain
        self.sts_record     = unicode(sts_record)
        self.via_dnssec     = dnssec
        self.is_policy      = False

        try:
            self.__split_up()
            self.is_policy = True
        except:
            # TODO: propper exception handling
            pass

    def get_policy(self):
        """returns all the policy data"""
        if self.is_policy:
            content = (
                self.v,
                self.a,
                self.c,
                self.e,
                self.to,
                self.rua,
                self.mx
            )
        else:
            content = False
        return content

    def expired(self):
        """checks if the policy is expired"""

        if self.cached_since + self.e > self.now:
            return False
        else:
            return True

    def __split_up(self):
        """splits up (parses) the _smtp-sts TXT-RR"""
        # TODO: Error handling everywhere.

        record =  {}
        y = [ x.strip() for x in self.sts_record.split(';') ]

        for x in y:
            (key, value) = x.split('=', 1)
            record[key]=value

        # v: Version (plain-text, required).  Currently only "STS1" is supported
        if record['v'] != "STS1":
            return False

        self.v = record['v']

        # e: Max lifetime of the policy (plain-text integer seconds)
        self.e = int(record['e'])

        # mx: MX patterns (comma-separated list of plain-text MX match patterns)
        self.mx = record['mx'].split(',')

        # to: TLS-Only (plain-text, required). If "true" the receiving MTA...
        if record['to'] == 'true':
            self.to = True
        else:
            self.to = False

        # a: The mechanism to use to authenticate this policy itself.
        if record['a'][0:6] == 'dnssec':
            self.a = { 'dnssec': self.via_dnssec } # None == unvalidated
        elif record['a'][0:6] == 'webpki':
            try:
                self.a = { 'webpki': 'https://%s/%s' % (self.domain, record['a'].split(':',1)[1], ) }
            except:
                self.a = { 'webpki': 'https://%s/.well-known/smtp-sts/current' % (self.domain,) }

        # c: Constraints on the recipient MX's TLS certificate
        if record['c'] not in ( 'webpki', 'tlsa', ):
            return False
        self.c = record['c']

        self.rua = record['rua']

        return True

# }}}

class SmtpSts(object): # {{{
    """docstring for SmtpSts"""
    def __init__(self, domain, mx_records, sts_record, cachedb_file, verbose=False):
        super(SmtpSts, self).__init__()
        self.domain     = domain

        self.sts_domain = "_smtp-sts.%s" % ( domain, )
        self.sts_record = sts_record
        self.mx_records = mx_records
        self.verbose    = verbose
        self.output     =''

        self.__cachedb  = sqlite3.connect(cachedb_file)

    def policy_from_cache(self):
        """get the policy from the cache"""
        p = False
        c = self.__cachedb.cursor()
        c.execute('SELECT sts_record, timestamp FROM sts_cache WHERE domain=?', ( self.domain, ))
        result = c.fetchone()
        if result:
            p = StsPolicy( domain = self.domain, sts_record = result[0], cached_since = result[1] )
            self.output += "Found in Cache; "
        return p

    def cache(self, policy):
        """cache this policy"""
        c = self.__cachedb.cursor()
        # I don't like updates.
        # TODO: use updates and make `domain` a primary key
        c.execute('INSERT INTO sts_cache ( domain, sts_record, timestamp ) VALUES (?, ?, ?)', ( policy.domain, policy.sts_record, policy.now, ) )
        c.execute('DELETE from sts_cache WHERE domain = ? AND timestamp < ? ', ( policy.domain, policy.now, ) )
        self.__cachedb.commit()
        self.output += "Updated Cache; "

    def policy_from_dns(self):
        """get the policy from DNS"""
        p = StsPolicy( domain = self.domain, sts_record = self.sts_record )
        return p

    def policy_from_webpki(self, uri):
        """get the policy from WebPKI"""
        # TODO: Exceptionhandling, if SSL fails, don't crash.
        sts_record = requests.get(uri).text
        p = StsPolicy(self.domain, sts_record)
        self.output += "Fetched Policy from webpki; "
        return p

    def validate_mx(self, policy):
        """validate the MX againts the policy"""
        r_MX = policy.mx
        d_MX = self.mx_records

        r_MX_patterns = {}

        # Build regex_patterns
        for r_mx in r_MX:
            regex_p = '%s.?$' % ( re.sub('\.', '\.', re.sub('_', '^[a-z0-1-]+' ,r_mx, 1)), )
            r_MX_patterns[r_mx] = re.compile(regex_p)

        passed = False

        for d_mx in d_MX:
            for r_mx in r_MX:
                if r_MX_patterns[r_mx].match(d_mx):
                    passed = True
                    if self.verbose: print '"%s" matches "%s"' % (d_mx, r_mx, )
                    self.output += '"%s" matches "%s"; ' % (d_mx, r_mx, )
                else:
                    if self.verbose: print '"%s" does not match "%s"' % (d_mx, r_mx, )

        return passed


    def validate(self):
        """validate the policies"""
        update_cache = False
        return_code = 0

        policy       = self.policy_from_cache()
        if not policy or policy.expired():

            if self.verbose: print "cache expired or no policy yet"
            self.output += "cache expired or no policy yet; "
            dns = self.policy_from_dns()
            if dns.is_policy:
                self.output += "Policy in DNS Found; "
                if dns.a['webpki']: # Authenticate via WebPKI
                    auth = self.policy_from_webpki(dns.a['webpki'])

                    if dns.get_policy() == auth.get_policy():
                        if self.verbose: print "Policys from DNS and WebPKI match: OK"
                        self.output += "Policys from DNS and WebPKI match: OK; "
                        # if they match, dns is the new policy
                        policy = dns
                        update_cache = True
                    else:
                        if self.verbose: print "Policys from DNS and WebPKI match: Failed"
                        self.output += "Policys from DNS and WebPKI match: Failed; "
                        return False

                elif dns.a['dnssec']: # Authenticate via dnssec
                    self.output += "Policys from DNS and DNSSEC match: OK; "

                else:
                    self.output += "Policys from DNS and ???? don't match: FAILED; "
                    return False

            else:
                self.output += "No Policy in DNS Found - No smtp-sts validation wanted; "
                return True

        else:
            if self.verbose: print "cache OK"

        if self.validate_mx(policy):
            if update_cache:
                self.cache(policy)
            return True

        return False

# }}}

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Verify SMTP-STS')
    parser.add_argument( '-d', '--domain',      metavar='DOMAIN',   type=str,   help='domain to test' )
    parser.add_argument( '-s', '--smtp-sts',    metavar='TXT',      type=str,   help='_smtp-sts TXT record' )
    parser.add_argument( '-m', '--mx',          metavar='MX',       type=str,  help='MXes (multiple times possible)', action="append" )
    parser.add_argument( '-c', '--cachedb',     metavar='FILENAME', type=str,   help='sqlite3 cachedb', default="/tmp/smtp-sts-cache.sqlite3" )
    parser.add_argument( '-D', '--dnssec',      action='store_true', help='DNSSEC was used used' )
    parser.add_argument( '-v', '--verbose',     action='store_true', help='verbose output' )
    args = parser.parse_args()

    s = SmtpSts(args.domain, args.mx, args.smtp_sts, args.cachedb, args.verbose)

    # TODO: different return-codes for different errors
    if s.validate():
        print s.output
        sys.exit(0)
    else:
        print s.output
        sys.exit(1)

# vim:fdm=marker:ts=4:sw=4:sts=4:ai:sta:et
