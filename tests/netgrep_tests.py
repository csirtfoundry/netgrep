#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from netgrep.feedfilter import FeedFilter
import tempfile

class filter_test(unittest.TestCase):
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
            print l
            lines += 1
        try:
            assert(lines == correct_count)
        except AssertionError, e:
            raise AssertionError, "Expected %d lines, got %d" % (correct_count, lines)

    def test_match_ip(self):
        # IP hosted in a country
        self.set_input("1.1.1.1")
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


class delim_guess(unittest.TestCase):

    def set_input(self, data):
        self.fh.write(data)
      
    def setUp(self):
        self.fh = tempfile.NamedTemporaryFile()

    def tearDown(self):
        self.fh.close()

    def assert_delim(self, delim, correct_delim):
        try:
            assert(delim == correct_delim)
        except AssertionError, e:
            raise AssertionError, "Expected delim '%s', got '%s'" % (correct_delim, delim)

    def test_comma_sep(self):
        self.set_input("1.1.1.1,2.2.2.2,3.3.3.3")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, ",")

    def test_comma_sep_with_quotes(self):
        self.set_input("'1.1.1.1','2.2.2.2','3.3.3.3'")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, ",")

    def test_comma_sep_with_spaces(self):
        self.set_input("1.1.1.1     ,    http://www.space.com     ,     Telephone network")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, ",")

    def test_pipe_sep_with_spaces(self):
        # TODO: fails on a single line of input, works it out with two
        self.set_input("1.1.1.1     |    http://www.space.com     |     Telephone network\n \
                        2.2.2.2     |    http://nextsite.com      |     ISP")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, "|")

    def test_multi_char_delim(self):
        # TODO: fails on a single line of input, works it out with two
        self.set_input("1.1.1.1~~http://www.space.com~~Telephone network")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, "~~")

    def test_many_escaped_fake_delims(self):
        self.set_input("'1\,1\,1\,1'\t'2\,2\,2\,2'")
        ng = FeedFilter(filter="AU", infile=self.fh)
        self.assert_delim(ng.delim, "\t")

    def test_guessed_delim_override(self):
        # by right, this should auto-guess the delmiter as ','.
        # make sure our manual override works.
        self.set_input("1,1,1,1\t2,2,2,2")
        ng = FeedFilter(filter="AU", infile=self.fh, delim='\t')
        self.assert_delim(ng.delim, "\t")


if __name__ == "__main__":
    unittest.main()
