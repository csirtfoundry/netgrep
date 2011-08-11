#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from netgrep.feedfilter import FeedFilter
import tempfile
import sys

class extract_resolve_test(unittest.TestCase):
    """ 
        since we're looking up domains and IP locations live, we can't guarantee
        consistent test results. I've tried to pick domains and IP I think are
        more stable than most. If a test fails, check the data against zcw etc
        first.
    """

    def set_input(self, data):
        self.fh.write(data)
      
    def setUp(self):
        self.fh = tempfile.NamedTemporaryFile()

    def tearDown(self):
        self.fh.close()

    def count_matches(self, ng, correct_count):
        lines = 0
        self.fh.seek(0)
        ng.process_file()
        for l in ng.get_filtered_lines():
            lines += 1
        try:
            assert(lines == correct_count)
        except AssertionError, e:
            raise AssertionError, "Expected %d lines, got %d" % (correct_count, lines)

    def test_match_ip(self):
        # IP hosted in a country. This is a .au Macquarie Telecom IP.
        self.set_input("210.193.134.1")
        ng = None
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)

    def test_nonmatch_ip(self):
        # IP not hosted in a country
        self.set_input("1.1.1.1")
        ng = None
        ng = FeedFilter(filter="ZZ", infile=self.fh)
        self.count_matches(ng, 0)

    def test_domain_cc_match(self):
        # domain CC matches CC?
        self.set_input("www.gov.au")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)

    def test_domain_ip_match(self):
        # domain hosted in another country. Hosting country match filter?
        self.set_input("www.google.com.au")
        ng = FeedFilter(filter="US", infile=self.fh)
        self.count_matches(ng, 1)

    def test_domain_ip_no_match(self):
        # Test no match for non-related domain
        self.set_input("www.bbc.co.uk")
        ng = FeedFilter(filter="AR", infile=self.fh)
        self.count_matches(ng, 0)

    def test_cc_too_early(self):
        # domain has country code which is not a TLD.
        # Example seems like it should match, but we can't go chasing
        # every two letter string.
        self.set_input("au.yahoo.com")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 0)

    def test_basic_url(self):
        self.set_input("http://www.pm.gov.au")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)

    def test_arg_url(self):
        # domain has country code which is not a TLD.
        # Example seems like it should match, but we can't go chasing
        # every two letter string.
        self.set_input("http://www.pm.gov.au/testing/?more_testing=testing")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)

    def test_irc(self):
        self.set_input("irc://Tampa.FL.US.Undernet.org")
        ng = FeedFilter(filter="US", infile=self.fh)
        self.count_matches(ng, 1)

    def test_at_url_credential(self):
        self.set_input("http://me@abc.net.au/")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)

    def test_unicode_non_address(self):
        # test unicode chars outside of a matchable IP address or hostname.
        # not quite ready to deal with unicode hostnames just yet.
        self.set_input("http://www.pm.gov.au/testing/?more_testing=testing,手巣戸")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.count_matches(ng, 1)


class extraction_test(unittest.TestCase):

    def set_input(self, data):
        self.fh.write(data)
      
    def setUp(self):
        self.fh = tempfile.NamedTemporaryFile()

    def tearDown(self):
        self.fh.close()

    def assert_matches(self, matches, correct_matches):
        #for line, linenum in enumerate(ng.infile.readline()):
        #    sys.stderr.write(line)
        #    matches.append(list(ng.extract_line_matches(line, linenum)))
        #    print matches
        #    print correct_matches
        try:
            #assert(list(matches))
            assert(matches == correct_matches)
        except AssertionError:
            raise AssertionError, (correct_matches, matches)
            #raise AssertionError, "Expected extraction [%s], got [%s]" % (", ".join("-".join(correct_matches)), ", ".join("-".join(matches)))

    def test_comma_sep(self):
        self.set_input("1.1.1.1,2.2.2.2,3.3.3.3")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [("ip", "1.1.1.1"), ("ip", "2.2.2.2"), ("ip", "3.3.3.3")])

    def test_comma_sep_with_quotes(self):
        self.set_input("'1.1.1.1','2.2.2.2','3.3.3.3'")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [("ip", "1.1.1.1"), ("ip", "2.2.2.2"), ("ip", "3.3.3.3")])

    def test_comma_sep_with_spaces(self):
        self.set_input("1.1.1.1     ,    http://www.space.com     ,     Telephone network")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [("ip", "1.1.1.1"), ("domain", "www.space.com")])

    def test_multi_line(self):
        self.set_input("1.1.1.1     |    http://www.space.com     |     Telephone network\n \
                        2.2.2.2     |    http://nextsite.com      |     ISP")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [("ip", "1.1.1.1"), ("domain", "www.space.com"), ("ip", "2.2.2.2"), ("domain", "nextsite.com")])

    def test_email_addy(self):
        self.set_input("a@sample.com")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [("domain", "sample.com")])

    def test_fake_tld(self):
        # we shouldn't extract domains that aren't domains
        self.set_input("not.a.domainatall")
        ng = FeedFilter(filter="AU", infile=self.fh)
        matches = list(ng.extract_matches())
        self.assert_matches(matches, [])


if __name__ == "__main__":
    unittest.main()
