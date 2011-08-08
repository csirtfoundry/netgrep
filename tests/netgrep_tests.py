import unittest
from netgrep.feedfilter import FeedFilter
import tempfile
import argparse
import sys

class default_args(object):

    def __init__(self):
        self.args = argparse.Namespace()
        self.args.verbose = False
        self.args.quiet = True
        self.args.has_header = False
        self.args.verboser = False
        self.args.format = None
        self.args.outfile = sys.stdout

    def set_input_file(self, data):
        #f = tempfile.NamedTemporaryFile("r+")
        f = open("/tmp/tester", "w")
        f.write(data)
        f.close()
        f = open("/tmp/tester", "r")
        return f
 
class basic_test(unittest.TestCase):
      
    def setUp(self):
        self.args = default_args()   

        #args = (self.argp.parse_args(['AU', '--infile=%s' % "/tmp/ddds"])) #self.get_file_name(inf)]))
        #args = args()
        #args = argparse.Namespace()
        self.args.args.filter = "AU"
        self.args.args.infile = self.args.set_input_file("203.21.203.254\nwww.hotmail.com.au")
        self.ng = FeedFilter(self.args.args)

    def tearDown(self):
        pass


    def test_singleline(self):
        print "Writing lines"
        lines = 0
        self.ng.process_file()
        for l in self.ng.get_filtered_lines():
            lines += 1
            print( "Line: %s" % l)

        assert(lines == 2)

if __name__ == "__main__":
    unittest.main()
