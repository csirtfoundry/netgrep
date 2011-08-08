import unittest
from netgrep.feedfilter import FeedFilter
import tempfile
import argparse
import sys

class default_setup(object):

    def __init__(self):
        self.args = argparse.Namespace()
        self.args.verbose = False
        self.args.quiet = True
        self.args.has_header = False
        self.args.verboser = False
        self.args.format = None
        self.args.outfile = sys.stdout

    def set_input_file(self, data):
        self.wf = tempfile.NamedTemporaryFile()
        self.wf.write(data)
        return self.wf
 
class basic_test(unittest.TestCase):
      
    def setUp(self):
        self.setup = default_setup()   

    def tearDown(self):
        self.setup.wf.close()
        pass

    def count_matches(self, ng, correct_count):
        lines = 0
        ng.process_file()
        for l in ng.get_filtered_lines():
            lines += 1
        assert(lines == correct_count)

    def test_singleline(self):
        #filter, matches, data = self.setup.parse_test_file()
        self.setup.args.filter = "AU"
        self.setup.args.infile = self.setup.set_input_file("203.21.203.254")
        ng = FeedFilter(self.setup.args)
        self.count_matches(ng, 1)

    def test_comma_parse(self):
        self.setup.args.filter = "AU"
        self.setup.args.infile = self.setup.set_input_file("203.21.203.254,www.example.com")
        self.ng = FeedFilter(self.setup.args)
        lines = 0
        self.ng.process_file()
        for l in self.ng.get_filtered_lines():
            lines += 1
            print( "Line: %s" % l)

        assert(lines == 1)

if __name__ == "__main__":
    unittest.main()
