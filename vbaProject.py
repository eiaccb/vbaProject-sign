
from io import BytesIO
from struct import unpack, pack
from binascii import hexlify
# dicts are already ordered in later Python versions, but...
from collections import OrderedDict
import hashlib
import re
import logging
logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

from officeparser import CompoundBinaryFile, decompress_stream

def setCodePage(project, raw_value):
    value = unpack('<H', raw_value)[0]
    project.codePage = value
    return value

# Name, Length, Encoding, Value, MatchRequired
dir_stream_root = ['root', 'dir_stream', 'INCLUDE', None, True]

# MS-OVBA https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba
dir_stream_syntax = {
    'dir_stream': [		# 2.3.4.2
        ['InformationRecord', 'PROJECTINFORMATION', 'INCLUDE', None, True],
        ['ReferencesRecord', 'PROJECTREFERENCES', 'INCLUDE', None, True],
        ['ModulesRecord', 'PROJECTMODULES', 'INCLUDE', None, True],
        ['Terminator', 2, 'H', 0x0010, True],
        ['Reserved', 4, 'L', 0x00000000, False],
    ],
    'PROJECTINFORMATION': [	# 2.3.4.2.1
        ['SysKindRecord', 'PROJECTSYSKIND', 'INCLUDE', None, True],
        ['CompatVersionRecord', 'PROJECTCOMPATVERSION', 'OPTINCLUDE', None, True],
        ['LcidRecord', 'PROJECTLCID', 'INCLUDE', None, True],
        ['LcidInvokeRecord', 'PROJECTLCIDINVOKE', 'INCLUDE', None, True],
        ['CodePageRecord', 'PROJECTCODEPAGE', 'INCLUDE', None, True],
        ['NameRecord', 'PROJECTNAME', 'INCLUDE', None, True],
        ['DocStringRecord', 'PROJECTDOCSTRING', 'INCLUDE', None, True],
        ['HelpFilePathRecord', 'PROJECTHELPFILEPATH', 'INCLUDE', None, True],
        ['HelpContextRecord', 'PROJECTHELPCONTEXT', 'INCLUDE', None, True],
        ['LibFlagsRecord', 'PROJECTLIBFLAGS', 'INCLUDE', None, True],
        ['VersionRecord', 'PROJECTVERSION', 'INCLUDE', None, True],
        ['ConstantsRecord', 'PROJECTCONSTANTS', 'OPTINCLUDE', None, True],
    ],
    'PROJECTSYSKIND': [		# 2.3.4.2.1.1
        ['Id', 2, 'H', 0x0001, True], 
        ['Size', 4, 'L', 0x00000004, True],
        ['SysKind', 4, 'L', [0x00000000, 0x00000001, 0x00000002, 0x00000003], True],
    ],
    'PROJECTCOMPATVERSION': [	# 2.3.4.2.1.2
        ['Id', 2, 'H', 0x004A, True],
        ['Size', 4, 'L', 0x00000004, True],
        ['CompatVersion', 4, 'L', None, True],
    ],
    'PROJECTLCID': [		# 2.3.4.2.1.3
        ['Id', 2, 'H', 0x0002, True],
        ['Size', 4, 'L', 0x00000004, True],
        ['Lcid', 4, 'L', 0x00000409, True],
    ],
    'PROJECTLCIDINVOKE': [	# 2.3.4.2.1.4
        ['Id', 2, 'H', 0x0014, True], 
        ['Size', 4, 'L', 0x00000004, True],
        ['LcdInvoke', 4, 'L', 0x00000409, True],
    ],
    'PROJECTCODEPAGE': [	# 2.3.4.2.1.5
        ['Id', 2, 'H', 0x0003, True], 
        ['Size', 4, 'L', 0x00000002, True],
        ['CodePage', 2, setCodePage, None, True],
    ],
    'PROJECTNAME': [		# 2.4.4.2.1.6
        ['Id', 2, 'H', 0x0004, True], 
        ['SizeOfProjectName', 4, 'L', None, True],
        ['ProjectName', 'SizeOfProjectName', 'MBCS', None, True],
    ],
    'PROJECTDOCSTRING': [	# 2.3.4.2.1.7
        ['Id', 2, 'H', 0x0005, True],
        ['SizeOfDocString', 4, 'L', lambda x: x <= 2000, True],
        ['DocString', 'SizeOfDocString', 'MBCS', None, True],
        ['Reserved', 2, 'H', 0x0040, False],
        ['SizeOfDocStringUnicode', 4, 'L', lambda x: x%2 == 0, True],
        ['DocStringUnicode', 'SizeOfDocStringUnicode', 'UTF-16', None, True],
    ],
    'PROJECTHELPFILEPATH': [	# 2.3.4.2.1.8
        ['Id', 2, 'H', 0x0006, True], 
        ['SizeOfHelpFile1', 4, 'L', lambda x: x<=260, True],
        ['HelpFile1', 'SizeOfHelpFile1', 'MBCS', None, True],
        ['Reserved', 2, 'H', 0x003d, False],
        ['SizeOfHelpFile2', 4, 'L', lambda x: x<=260, True],
        ['HelpFile2', 'SizeOfHelpFile2', 'MBCS', None, True],
    ],
    'PROJECTHELPCONTEXT': [	# 2.3.4.2.1.9
        ['Id', 2, 'H', 0x0007, True], 
        ['Size', 4, 'L', 0x00000004, True],
        ['HelpContext', 4, 'L', None, True],
    ],
    'PROJECTLIBFLAGS': [	# 2.3.4.2.1.10
        ['Id', 2, 'H', 0x0008, True],
        ['Size', 4, 'L', 0x00000004, True],
        ['ProjectLibFlags', 4, 'L', None, True],
    ],
    'PROJECTVERSION': [		# 2.3.4.2.1.11
        ['Id', 2, 'H', 0x0009, True], 
        ['Reserved', 4, 'L', 0x00000004, False], 
        ['VersionMajor', 4, 'L', None, True],
        ['VersionMinor', 2, 'H', None, True],
    ],
    'PROJECTCONSTANTS': [	# 2.3.4.2.1.12
        ['Id', 2, 'H', 0x000C, True],
        ['SizeOfConstants', 4, 'L', lambda x: x <= 1015, True],
        ['Constants', 'SizeOfConstants', 'MBCS', None, True],
        ['Reserved', 2, 'H', 0x003C, False],
        ['SizeOfConstantsUnicode', 4, 'L', lambda x: x%2 == 0, True],
        ['ConstantsUnicode', 'SizeOfConstantsUnicode', 'UTF-16', None, True],
    ],
    'PROJECTREFERENCES': [	# 2.3.4.2.2
        ['ReferenceArray', 'REFERENCE', 'ARRAY', None, True],
    ],
    'REFERENCE': [		# 2.3.4.2.2.1
        ['NameRecord', 'REFERENCENAME', 'OPTINCLUDE', None, True],
        ['ReferenceRecord', ['REFERENCECONTROL','REFERENCEORIGINAL','REFERENCEREGISTERED','REFERENCEPROJECT'], 'CHOICEINCLUDE', None, True],
    ],
    'REFERENCENAME': [		# 2.3.4.2.2.2
        ['Id', 2, 'H', 0x0016, True],
        ['SizeOfName', 4, 'L', None, True],
        ['Name', 'SizeOfName', 'MBCS', None, True],
        ['Reserved', 2, 'H', None, False],
        ['SizeOfNameUnicode', 4, 'L', None, True],
        ['NameUnicode', 'SizeOfNameUnicode', 'UTF-16', None, True],
    ],
    'REFERENCECONTROL': [	# 2.3.4.2.2.3
        ['Id', 2, 'H', 0x002F, True],
        ['SizeTwiddled', 4, 'L', None, True],
        ['SizeOfLibidTwiddled', 4, 'L', None, True],
        ['LibidTwiddled', 'SizeOfLibidTwiddled', 'MBCS', None, True],
        ['Reserved1', 4, 'L', 0x00000000, False],
        ['Reserved2', 2, 'H', 0x0000, False],
        ['NameRecordExtended', 'REFERENCENAME', 'OPTINCLUDE', None, True],
        ['Reserved3', 2, 'H', 0x0030, False],
        ['SizeExtended', 4, 'L', None, True],
        ['SizeOfLibidExtended', 4, 'L', None, True],
        ['LibExtended', 'SizeOfLibidExtended', 'MBCS', None, True],
        ['Reserved4', 4, 'L', 0x00000000, False],
        ['Reserved5', 2, 'H', 0x0000, False],
        ['OriginalTypeLib', 16, 'BYTES', None, True],
        ['Cookie', 4, 'L', None, True],
    ],
    'REFERENCEORIGINAL': [	# 2.3.4.2.2.4
        ['Id', 2, 'H', 0x0033, True],
        ['SizeOfLibidOriginal', 4, 'L', None, True],
        ['LibidOriginal', 'SizeOfLibidOriginal', 'MBCS', None, True],
        ['ReferenceRecord', 'REFERENCECONTROL', 'INCLUDE', None, True],
    ],
    'REFERENCEREGISTERED': [	# 2.3.4.2.2.5
        ['Id', 2, 'H', 0x000D, True],
        ['Size', 4, 'L', None, True],
        ['SizeOfLibid', 4, 'L', None, True],
        ['Libid', 'SizeOfLibid', 'MBCS', None, True],
        ['Reserved1', 4, 'L', 0x00000000, False],
        ['Reserved2', 2, 'H', 0x0000, False],
    ],
    'REFERENCEPROJECT': [	# 2.3.4.2.2.6
        ['Id', 2, 'H', 0x000E, True],
        ['Size', 4, 'L', None, True],
        ['SizeOfLibidAbsolute', 4, 'L', None, True],
        ['LibidAbsolute', 'SizeOfLibidAbsolute', 'MBCS', None, True],
        ['SizeOfLibidRelative', 4, 'L', None, True],
        ['LibidRelative', 'SizeOfLibidRelative', 'MBCS', None, True],
        ['MajorVersion', 4, 'L', None, True],
        ['MinorVersion', 2, 'H', None, True]
    ],
    'PROJECTMODULES': [		# 2.3.4.2.3
        ['Id', 2, 'H', 0x000F, True],
        ['Size', 4, 'L', 0x00000002, True],
        ['Count', 2, 'H', None, True],
        ['ProjectCookieRecord', 'PROJECTCOOKIE', 'INCLUDE', None, True],
        ['Modules', 'MODULE', 'ARRAY', None, True],
    ],
    'PROJECTCOOKIE': [		# 2.3.4.2.3.1
        ['Id', 2, 'H', 0x0013, True],
        ['Size', 4, 'L', 0x00000002, False],
        ['Cookie', 2, 'H', None, False], # 0xFFFF supposedly, but it cjamges
    ],
    'MODULE': [			# 2.3.4.2.3.2
        ['NameRecord', 'MODULENAME', 'INCLUDE', None, True],
        ['NameUnicodeRecord', 'MODULENAMEUNICODE', 'OPTINCLUDE', None, True],
        ['StreamNameRecord', 'MODULESTREAMNAME', 'INCLUDE', None, True],
        ['DocStringRecord', 'MODULEDOCSTRING', 'INCLUDE', None, True],
        ['OffsetRecord', 'MODULEOFFSET', 'INCLUDE', None, True],
        ['HelpContextRecord', 'MODULEHELPCONTEXT', 'INCLUDE', None, True],
        ['CookieRecord', 'MODULECOOKIE', 'INCLUDE', None, True],
        ['TypeRecord', 'MODULETYPE', 'INCLUDE', None, True],
        ['ReadOnlyRecord', 'MODULEREADONLY', 'OPTINCLUDE', None, True],
        ['PrivateRecord', 'MODULEPRIVATE', 'OPTINCLUDE', None, True],
        ['Terminator', 2, 'H', 0x002B, True],
        ['Reserved', 4, 'L', 0x00000000, False],
    ],
    'MODULENAME': [		# 2.3.4.2.3.2.1
        ['Id', 2, 'H', 0x0019, True],
        ['SizeOfModuleName', 4, 'L', None, True],
        ['ModuleName', 'SizeOfModuleName', 'MBCS', None, True],
    ],
    'MODULENAMEUNICODE': [	# 2.3.4.2.3.2.2
        ['Id', 2, 'H', 0x0047, True],
        ['SizeOfModuleNameUnicode', 4, 'L', None, True],
        ['ModuleNameUnicode', 'SizeOfModuleNameUnicode', 'UTF-16', None, True],
    ],
    'MODULESTREAMNAME': [	# 2.3.4.2.3.2.3
        ['Id', 2, 'H', 0x001A, True],
        ['SizeOfStreamName', 4, 'L', None, True],
        ['StreamName', 'SizeOfStreamName', 'MBCS', None, True],
        ['Reserved', 2, 'H', 0x0032, False],
        ['SizeOfStreamNameUnicode', 4, 'L', None, True],
        ['StreamNameUnicode', 'SizeOfStreamNameUnicode', 'UTF-16', None, True],
    ],
    'MODULEDOCSTRING': [	# 2.3.4.2.3.2.4
        ['Id', 2, 'H', 0x001C, True],
        ['SizeOfDocString', 4, 'L', None, True],
        ['DocString', 'SizeOfDocString', 'MBCS', None, True],
        ['Reserved', 2, 'H', 0x0048, False],
        ['SizeOfDocStringUnicode', 4, 'L', None, True],
        ['DocStringUnicode', 'SizeOfDocStringUnicode', 'UTF-16', None, True],
    ],
    'MODULEOFFSET': [		# 2.3.4.2.3.2.5
        ['Id', 2, 'H', 0x0031, True],
        ['Size', 4, 'L', 0x00000004, True],
        ['TextOffset', 4, 'L', None, True],
    ],
    'MODULEHELPCONTEXT': [	# 2.3.4.2.3.2.6
        ['Id', 2, 'H', 0x001E, True],
        ['Size', 4, 'L', 0x00000004, True],
        ['HelpContext', 4, 'L', None, True],
    ],
    'MODULECOOKIE': [		# 2.3.4.2.3.2.7
        ['Id', 2, 'H', 0x002C, True],
        ['Size', 4, 'L', 0x00000002, True],
        ['Cookie', 2, 'H', None, True], # 0xFFFF supposedly, but it changes
    ],
    'MODULETYPE': [		# 2.3.4.2.3.2.8
        ['Id', 2, 'H', [0x0021,0x0022], True],
        ['Reserved', 4, 'L', 0x00000000, False],
    ],
    'MODULEREADONLY': [		# 2.3.4.2.3.2.9
        ['Id', 2, 'H', [0x0021,0x0025], True],
        ['Reserved', 4, 'L', 0x00000000, False],
    ],
    'MODULEPRIVATE': [		# 2.3.4.2.3.2.10
        ['Id', 2, 'H', [0x0021,0x0028], True],
        ['Reserved', 4, 'L', 0x00000000, False],
    ],
}

def abridge(buffer):
    length = len(buffer)
    tail = buffer[-1]
    initial = len(buffer.rstrip(bytes([tail])))
    if length - initial > 16:
        return buffer[:initial + 3]
    else:
        return buffer

class NormalizedReporter:

    class EndOfData(Exception):
        pass

    def __init__(self, data, addrprefix=False):
        self.data = data
        self.pos = 0
        self.addrprefix = addrprefix

    def report_short(self, name, expected=None):
        field = unpack('<H', self.data[self.pos:self.pos + 2])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 2, name, field))
        else:
            print("({}) {} = {}".format(2, name, field))
        if expected is not None:
            if field != expected:
                print("Error: Expected %d, found %d [%s...]" % (expected, field, hexlify(self.data[self.pos:self.pos+32])))
        self.pos += 2

    def report_id(self, name, expected=None):
        field = unpack('<H', self.data[self.pos:self.pos + 2])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = 0x{:04X}".format(self.pos, 2, name, field))
        else:
            print("({}) {} = 0x{:04X}".format(2, name, field))
        if expected is not None:
            if field != expected:
                print("Error: Expected %d, found %d [%s...]" % (expected, field, hexlify(self.data[self.pos:self.pos+32])))
        self.pos += 2

    def next_id(self):
        field = unpack('<H', self.data[self.pos:self.pos + 2])[0]
        return field

    def report_long(self, name, expected=None):
        field = unpack('<L', self.data[self.pos:self.pos + 4])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 4, name, field))
        else:
            print("({}) {} = {}".format(2, name, field))
        if expected is not None:
            if field != expected:
                print("Error: Expected %d, found %d [%s...]" % (expected, field, hexlify(self.data[self.pos:self.pos+32])))
        self.pos += 4

    def report_string(self, sizename, name):
        size = unpack('<L', self.data[self.pos:self.pos + 4])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 4, sizename, size))
        else:
            print("({}) {} = {}".format(2, sizename, size))
        self.pos += 4
        field = unpack('<{0}s'.format(size), self.data[self.pos:self.pos+size])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size, name, field))
        else:
            print("({}) {} = {}".format(size, name, field))
        self.pos += size
        
    def report_unicode(self, sizename, name):
        size = unpack('<L', self.data[self.pos:self.pos + 4])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 4, sizename, size))
        else:
            print("({}) {} = {}".format(2, sizename, size))
        self.pos += 4
        field = unpack('<{0}s'.format(size), self.data[self.pos:self.pos+size])[0].decode('UTF-16-LE')
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size, name, field))
        else:
            print("({}) {} = {}".format(size, name, field))
        self.pos += size
        
    def report_weird_unicode(self, sizename, name):
        size = unpack('<L', self.data[self.pos:self.pos + 4])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 4, sizename, size))
        else:
            print("({}) {} = {}".format(2, sizename, size))
        self.pos += 4
        field = unpack('<{0}s'.format(size*2), self.data[self.pos:self.pos+size*2])[0].decode('UTF-16-LE')
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size*2, name, field))
        else:
            print("({}) {} = {}".format(size*2, name, field))
        self.pos += size*2
        
    def report_bytes(self, sizename, name):
        size = unpack('<L', self.data[self.pos:self.pos + 4])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, 2, sizename, size))
        else:
            print("({}) {} = {}".format(2, sizename, size))
        self.pos += 4
        field = unpack('<{0}s'.format(size), self.data[self.pos:self.pos+size])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size, name, hexlify(field)))
        else:
            print("({}) {} = {}".format(size, name, hexlify(field)))
        self.pos += size

    def report_guid(self, name):
        size = 16
        field = unpack('<16s', self.data[self.pos:self.pos + size])[0]
        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size, name, hexlify(field)))
        else:
            print("({}) {} = {}".format(size, name, hexlify(field)))
        self.pos += size

    def report_line(self, name):
        end = self.data[self.pos:].find(b'\n')
        if end >= 0:
            size = end + 1
            field = self.data[self.pos:self.pos+size]
        else:
            # field = self.data[self.pos:]
            raise ValueError('No end: %s...' % hexlify(self.data[self.pos:]))

        if self.addrprefix:
            print("{:04X} ({}) {} = {}".format(self.pos, size, name, field))
        else:
            print("({}) {} = {}".format(size, name, field))

        self.pos += size

    def get_and_report_buffer(self, name, length):
        size = min(length, len(self.data) - self.pos)
        if size == 0:
            raise NormalizedReporter.EndOfData

        max_length = 1024
        extraction = unpack('<{0}s'.format(size), self.data[self.pos:self.pos+size])[0]
        field = abridge(extraction)
        if len(field) < len(extraction):
            dots = '...'
        else:
            dots = ''
        if self.addrprefix:
            print("{:04X} ({}) {} = {}{}".format(self.pos, size, name, hexlify(field), dots))
            print("{:04X} ({}) {} = {}{}".format(self.pos, size, name, field[:max_length], dots))
        else:
            print("({}) {} = {}{}".format(size, name, hexlify(field), dots))
            print("({}) {} = {}{}".format(size, name, field[:max_length], dots))
        self.pos += size
        return field

    def report_match(self, exp, name='XXX'):
        m = re.match(exp, self.data[self.pos:])
        max_length = 512
        if m:
            field = m.group(0)
            size = len(field)
            if self.addrprefix:
                print("{:04X} ({}) {} = {}".format(self.pos, size, name, hexlify(field)))
                print("{:04X} ({}) {} = {}".format(self.pos, size, name, field[:max_length]))
            else:
                print("({}) {} = {}".format(size, name, hexlify(field)))
                print("({}) {} = {}".format(size, name, field[:max_length]))

            self.pos += size
            return m

        else:
            return None

    def dump_rest(self):
        print("Rest (%d): %s... %s" % (
            len(self.data[self.pos:]),
            self.data[self.pos:self.pos+32],
            hexlify(self.data[self.pos:])))
        
def V3ContentNormalizedData_analyze(reporter):
    r = reporter

    r.report_id('PROJECTSYSKIND.Id', expected=0x0001)
    r.report_long ('PROJECTSYSKIND.Size')

    r.report_id('PROJECTLCID.Id', expected=0x0002)
    r.report_long ('PROJECTLCID.Size', expected=0x00000004)
    r.report_long ('PROJECTLCID.Lcid', expected=0x00000409)

    r.report_id('PROJECTLCIDINVOKE.Id', expected=0x0014)
    r.report_long ('PROJECTLCIDINVOKE.Size', expected=0x00000004)
    r.report_long ('PROJECTLCIDINVOKE.Lcid', expected=0x00000409)

    r.report_id('PROJECTCODEPAGE.Id', expected=0x0003)
    r.report_long ('PROJECTCODEPAGE.Size', expected=0x00000002)

    r.report_id('PROJECTNAME.Id', expected=0x0004)
    r.report_string('PROJECTNAME.SizeOfProjectName', 'PROJECTNAME.ProjectName')

    r.report_id('PROJECTDOCSTRING.Id', expected=0x0005)
    r.report_long ('PROJECTDOCSTRING.SizeOfDocString')
    r.report_short('PROJECTDOCSTRING.Reserved', expected=0x0040)
    r.report_long ('PROJECTDOCSTRING.SizeOfDocStringUnicode')

    r.report_id('PROJECTHELPFILEPATH.Id', expected=0x0006)
    r.report_long ('PROJECTHELPFILEPATH.SizeOfHelpFile1')
    r.report_short('PROJECTHELPFILEPATH.Reserved', expected=0x003D)
    r.report_long ('PROJECTHELPFILEPATH.SizeOfHelpFile2')

    r.report_id('PROJECTHELPCONTEXT.Id', expected=0x0007)
    r.report_long ('PROJECTHELPCONTEXT.Size')

    r.report_id('PROJECTLIBFLAGS.Id', expected=0x0008)
    r.report_long ('PROJECTLIBFLAGS.Size', expected= 0x00000004)
    r.report_long ('PROJECTLIBFLAGS.ProjectLibFlags', expected=0x00000000)

    r.report_id('PROJECTVERSION.Id', expected=0x0009)
    r.report_long ('PROJECTVERSION.Reserved', expected=0x00000004)
    r.report_long ('PROJECTVERSION.VersionMajor')
    r.report_short('PROJECTVERSION.VersionMinor')

    r.report_id('PROJECTCONSTANTS.Id', expected=0x00C)
    r.report_string('PROJECTCONSTANTS.SizeOfConstants', 'PROJECTCONSTANTS.Constants')
    r.report_short('PROJECTCONSTANTS.Reserved', expected=0x03C)
    r.report_string('PROJECTCONSTANTS.SizeOfConstantsUnicode', 'PROJECTCONSTANTS.ConstantsUnicode')

    while True:
        next_id = r.next_id()

        if next_id == 0x0016:

            r.report_id('REFERENCENAME.Id', expected=0x0016)
            r.report_string('REFERENCENAME.SizeOfName', 'REFERENCENAME.Name')
            r.report_short('REFERENCENAME.Reserved')
            r.report_unicode('REFERENCENAME.SizeOfNameUnicode', 'REFERENCENAME.NameUnicode')
            next_id = r.next_id()

        if next_id == 0x002F:

            r.report_id('REFERENCE.ReferenceControl.Id', expected=0x002F)
            r.report_string('REFERENCE.ReferenceControl.SizeOfLibidTwiddled', 'REFERENCE.ReferenceControl.LibidTwiddled')
            r.report_long('REFERENCE.ReferenceControl.Reserved1', expected=0x00000000)
            r.report_short('REFERENCE.ReferenceControl.Reserved2', expected=0x0000)
            next_id = r.next_id()
            if next_id == 0x0016:
                r.report_id('REFERENCE.ReferenceControl.NameRecordExtended.Id', expected=0x0016)
                r.report_string('REFERENCE.ReferenceControl.NameRecordExtended.Size', 'REFERENCE.ReferenceControl.NameRecordExtended.Name')
                next_id = r.next_id()
                if next_id == 0x003E:
                    r.report_id('REFERENCE.ReferenceControl.NameRecordExtended.Reserved')
                    r.report_unicode('REFERENCE.ReferenceControl.NameRecordExtended.SizeOfNameUnicode', 'REFERENCE.ReferenceControl.NameRecordExtended.NameUnicode')

            r.report_short('REFERENCE.ReferenceControl.Reserved3', expected=0x0030)
            r.report_string('REFERENCE.ReferenceControl.SizeOfLibidExtended', 'REFERENCE.ReferenceControl.LibidExtended')
            r.report_long('REFERENCE.ReferenceControl.Reserved4', expected=0x00000000)
            r.report_short('REFERENCE.ReferenceControl.Reserved5', expected=0x0000)
            r.report_guid('REFERENCE.ReferenceControl.OriginalTypeLib')
            r.report_long('REFERENCE.ReferenceControl.Cookie')

        elif next_id == 0x0033:
            r.report_id('REFERENCE.ReferenceOriginal.Id', expected=0x0033)
            r.report_string('REFERENCE.ReferenceOriginal.SizeOfLibidOriginal', 'REFERENCE.ReferenceOriginal.LibidOriginal')

        elif next_id == 0x000D:
            r.report_id('REFERENCE.ReferenceRegistered.Id', expected=0x000D)
            r.report_weird_unicode('REFERENCE.ReferenceRegistered.SizeOfLibid', 'REFERENCE.ReferenceRegistered.Libid')
            r.report_long('REFERENCE.ReferenceRegistered.Reserved1', expected=0x00000000)
            r.report_short('REFERENCE.ReferenceRegistered.Reserved2', expected=0x0000)

        elif next_id == 0x000E:
            r.report_id('REFERENCE.ReferenceProject.Id', expected=0x000E)
            r.report_string('REFERENCE.ReferenceProject.SizeOfLibidAbsolute', 'REFERENCE.ReferenceProject.LibidAbsolute')
            r.report_string('REFERENCE.ReferenceProject.SizeOfLibidRelative', 'REFERENCE.ReferenceProject.LibidRelative')
            r.report_long('REFERENCE.ReferenceProject.MajorVersion')
            r.report_short('REFERENCE.ReferenceProject.MinorVersion')

        else:
            break

    r.report_id('PROJECTMODULES.Id', expected=0x000F)
    r.report_long('PROJECTMODULES.Size', expected=0x00000002)
    r.report_id('PROJECTCOOKIE.Id', expected=0x0013)
    r.report_long('PROJECTCOOKIE.Size', expected=0x00000002)
    
    while True:
        next_id = r.next_id()
        if next_id == 0x010:
            break

        if next_id == 0x21:
            r.report_id('MODULE.TypeRecord.Id', expected=0x0021)
            r.report_long('MODULE.TypeRecord.Reserved',expected=0x00000000)
            next_id == r.next_id()

        if next_id == 0x0025:
            r.report_id('MODULE.ReadOnlyRecord.Id', expected=0x0025)
            r.report_long('MODULE.ReadOnlyRecord.Reserved', expected=0x00000000)
            next_id == r.next_id()

        if next_id == 0x0028:
            r.report_id('MODULE.PrivateRecord.Id', expected=0x0028)
            r.report_long('MODULE.PrivateRecord.Reserved', expected=0x00000000)
            next_id == r.next_id()

        finished = False
        while True:
            r.report_line('MODULE Text')
            next_id = r.next_id()
            # print("next_id = 0x%02X" % next_id)
            if next_id in (0x10, 0x21, 0x25, 0x28):
                finished = True
                break

    r.report_id('Terminator', expected=0x010)
    r.report_long('Reserved', expected=0x00000000)

# MS-OVBA 2.4.2.6 Project Normalized Data
def ProjectNormalizedData_analyze(reporter):
    r = reporter

    while True:
        match = r.report_match(rb'(ID|Document|Module|Class|BaseClass|Package|HelpFile|Exename32|Name|HelpContextID|Description|VersionCompatible32|CMG|DPB|GC)[^\0]*', 'ProjectNormalizedData')
        if match:
            continue

        try:
            r.get_and_report_buffer('ProjectNormalizedData', 1023)
        except NormalizedReporter.EndOfData:
            break

# MS-OVBA 2.4.2.7 V3 Content Hash
def V3ContentHash_analyze(data, addrprefix=False):
    pos = 0

    r = NormalizedReporter(data, addrprefix)

    V3ContentNormalizedData_analyze(r)
    ProjectNormalizedData_analyze(r)

    r.dump_rest()

class CheckFailed(Exception):
    pass

class Reporter:

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def report(self, text='Report'):
        new_pos = len(self.data)
        length = new_pos - self.pos
        logger.debug("%s: 0x%00X-0x%00X 0x%00X (%d): %s" % (
            text, self.pos, new_pos, length, length, hexlify(self.data[self.pos:])))
        self.pos = new_pos

class VBA_Storage:

    def __init__(self, vba_project):
        self.vbaProject = vba_project
        # MS-OVBA 2.3.4.1
        self._VBA_PROJECT_stream = None
        # MS-OVBA 2.3.4.2
        self._dir_stream = None
        self._parsed_dir_stream = None
        # MS-OVBA 2.3.4.3
        self._module_streams = None

    @property
    def dir_stream(self):

        if not self._dir_stream:
            dir_stream = self.vbaProject.cbf.find_stream_by_name('dir')
            if dir_stream is None:
                raise ValueError('missing dir stream')
            self._dir_stream = decompress_stream(self.vbaProject.cbf.get_stream(dir_stream.index))
        return self._dir_stream
           
    @property
    def parsed_dir_stream(self):
        if not self._parsed_dir_stream:
            self._parsed_dir_stream = self.vbaProject.parse_dir_stream(self.dir_stream)
        return self._parsed_dir_stream
    
class vbaProject():

    def __init__(self):
        self.cbf = None
        self._PROJECT_stream = None
        self._parsed_PROJECT_stream = None
        self.VBA_Storage = VBA_Storage(self)
        self.codePage = None
        
    @property
    def PROJECT_stream(self):
        if not self._PROJECT_stream:
            project_stream_info = self.cbf.find_stream_by_name('PROJECT')
            if project_stream_info is None:
                logger.error('missing PROJECT stream')
            self._PROJECT_stream = self.cbf.get_stream(project_stream_info.index)
            logger.debug("Project Stream: %s" % self._PROJECT_stream)
        return self._PROJECT_stream

    @property
    def parsed_PROJECT_stream(self):
        if not self._parsed_PROJECT_stream:
            self._parsed_PROJECT_stream = self.parse_project_stream(self.PROJECT_stream)
        return self._parsed_PROJECT_stream

    @property
    def parsed_dir_stream(self):
        return self.VBA_Storage.parsed_dir_stream
    
    @classmethod
    def parse(cls, source):
        obj = cls()
        
        if isinstance(source, str):
            obj.cbf = CompoundBinaryFile(source)
        elif isinstance(source, bytes):
            data = BytesIO(source)
            obj.cbf = CompoundBinaryFile(data)

        else:
            logger.error("Error, type is: %s" % type(source))

        return obj

    @property
    def projectName(self):
        if not hasattr(self, '_projectName'):
            self._projectName = None
        if not self._projectName:
            data = self.get_stream_by_path('PROJECT')
            for line in data.split(b'\r\n'):
                logger.debug(line)
            logger.debug(data)
            return 
            self._projectName = self.find_projectName()
        return self._projectName

    # Should work mid record too
    def first_ids(self, record_label, syntax):
        '''Compute the possible IDs that start some record'''

        record_def = syntax[record_label]

        valid_ids = []
        for fdef in record_def:
            fname, flength, ftype, fcheck, fmatch_required = fdef
            if ftype in ['INCLUDE', 'OPTINCLUDE']:
                valid_ids.extend(self.first_ids(flength, syntax))
                logger.debug("Valid ids from includes: %s" % valid_ids)
                if ftype == 'INCLUDE':
                    # Non optional include found, no need to go further
                    return valid_ids
            elif ftype == 'CHOICEINCLUDE':
                for choice in flength:
                    valid_ids.extend(self.first_ids(choice, syntax))
                logger.debug("Valid ids from choices: %s" % valid_ids)
                return valid_ids
            else:
                if fname == 'Id':
                    ids = fdef[3]
                    if isinstance(ids, list):
                        valid_ids.extend(ids)
                    else:
                        valid_ids.append(ids)
                # Non optional field found, no need to go further
                return valid_ids
        raise ValueError("Can't happen")

    def mbcs_fix_encode(self, item):
        '''Apparently there is some unexpected interpretation of 
        MBCS in the specification. In one particular case means
        to output a UTF-16-LE encoding'''
        code_page = self.codePage
        if code_page == 1252:
            encoding = 'windows-1252'
        else:
            logger.error("Unimplemented code page %s (%s)" % (code_page, type(code_page)))
            return item['value']

        return item['raw_value'].decode(encoding).encode('utf-16-le')

    def parse_one_field(self, source, definition, syntax, parent, context):
        logger.debug("Definition: %s" % definition)
        fname, flength, ftype, fcheck, fmatch_required = definition

        field_value = None

        if ftype in ['OPTINCLUDE', 'INCLUDE']:
            included_label = flength
            included_syntax = syntax[included_label]
            include = True
            next_id = unpack('<H', source['buffer'][source['pos']:source['pos']+2])[0]
            if ftype == 'OPTINCLUDE':
                # Assume that all included things have an Id as first field
                valid_next_ids = included_syntax[0][3]
                if not isinstance(valid_next_ids, list):
                    valid_next_ids = (valid_next_ids,)
                if next_id not in valid_next_ids:
                    logger.debug("Not present optional %s - %s (next_id = 0x%04x)" % (fname, flength, next_id))
                    include = False

            if include:
                logger.debug("Including %s (0x%04x)" % (fname, next_id))
                field_value = dict()
                for fdef in syntax[included_label]:
                    try:
                        val = self.parse_one_field(source, fdef, syntax, included_label, field_value)
                        field_value[fdef[0]] = val
                    except CheckFailed as e:
                        print(e)
                        raise CheckFailed("Parsing %s" % fname)
            return field_value

        elif ftype == 'ARRAY':
            elements = []
            included_label = flength

            included_syntax = syntax[included_label]

            logger.debug("Parsing ARRAY of %s" % included_label)
            # Assume that all included things have an Id as first field
            valid_next_ids = self.first_ids(included_label, syntax)

            logger.debug("Valid next ids: %s" % valid_next_ids)

            while True:
                next_id = unpack('<H', source['buffer'][source['pos']:source['pos']+2])[0]
                if next_id not in valid_next_ids:
                    logger.debug("Breaking out from array loop, id 0x%04x not in %s" % (next_id, valid_next_ids))
                    break
                elt = dict()
                for adef in syntax[included_label]:
                    logger.debug("In %s: field: %s" % (included_label, adef))
                    try:
                        val = self.parse_one_field(source, adef, syntax, included_label, elt)
                        elt[adef[0]] = val
                    except CheckFailed as e:
                        print(e)
                        raise CheckFailed("Parsing %s" % fname)

                logger.debug("Array element: %s" % elt)
                elements.append(elt)

            logger.debug("Returning ARRAY of %s with %d elements" % (included_label, len(elements)))
            return elements

        elif ftype == 'CHOICEINCLUDE':
            next_id = unpack('<H', source['buffer'][source['pos']:source['pos']+2])[0]
            logger.debug("Next id for choice: 0x%04x" % next_id)
            alternatives = flength
            for included_label in alternatives:
                included_syntax = syntax[included_label]
                valid_next_ids = included_syntax[0][3]
                if not isinstance(valid_next_ids, list):
                    valid_next_ids = (valid_next_ids,)

                if next_id in valid_next_ids:
                    # Choice matched
                    logger.debug("Matched %s" % included_label)
                    elt = dict()
                    for cdef in syntax[included_label]:
                        try:
                            val = self.parse_one_field(source, cdef, syntax, included_label, elt)
                            elt[cdef[0]] = val
                        except CheckFailed as e:
                            print(e)
                            raise CheckFailed("Parsing %s" % fname)
                    return elt
                else:
                    logger.debug("No match for 0x%04x in [%s]" % (next_id, ','.join(["0x%04x" % x for x in valid_next_ids])))
            else:
                raise CheckFailed("No record matched choice for %s" % fname)

        else:
            # Scalar

            if isinstance(flength, str):
                flength = context[flength]['value']

            current_pos = source['pos']

            raw_value = source['buffer'][current_pos:current_pos+flength]
            if ftype == 'MBCS':
                value = raw_value
            elif ftype == 'UTF-16':
                value = raw_value.decode('utf-16')
            elif ftype and callable(ftype):
                value = ftype(self, raw_value)
            elif len(ftype) == 1:
                value = unpack('<'+ftype, raw_value)[0]
            else:
                raise ValueError('Unknown type %s' % ftype)

            valid = True
            if fcheck is not None:
                if callable(fcheck):
                    valid = fcheck(value)
                elif isinstance(fcheck, list):
                    valid = value in fcheck
                else:
                    valid = value == fcheck

            field_value = {
                'raw_value': raw_value,
                'value': value,
            }

            if not valid:
                if fmatch_required:
                    raise CheckFailed("Invalid value %s for Field %s in %s" % (value, fname, parent))
                else:
                    logger.error("Invalid value %s for Field %s in %s" % (value, fname, parent))

            current_pos += flength
            source['pos'] = current_pos

        return field_value

    def parse_dir_stream(self, dir_stream):

        logger.debug("Parsing dir_stream")
        
        source = {
            'buffer': dir_stream,
            'pos': 0
        }

        # Name, Length, Encoding, Value, MatchRequired

        info = self.parse_one_field(
            source,
            dir_stream_root,
            dir_stream_syntax,
            'dir_info',
            None)

        logger.debug("Parsed dir_stream: %s" % info)

        self.dir_info = info

        logger.debug(info.keys())
        logger.debug(info['InformationRecord']['CodePageRecord']['CodePage'].keys())
        
        logger.debug("CodePage: %d" % self.codePage)
        PROJECTNAME = info['InformationRecord']['NameRecord']
        ProjectName = PROJECTNAME['ProjectName']['raw_value']
        logger.info("ProjectName: <%s> (%d bytes)" % (hexlify(ProjectName), len(ProjectName)))

        logger.debug("parsed_dir_stream: %s" % info)
        return info

    # The VBA storage contains the _VBA_PROJECT Stream (section 2.3.4.1),
    # the dir Stream (section 2.3.4.2), and Module Streams (section 2.3.4.3)
    # for the VBA project. It also contains optional SRP Streams
    # (section 2.2.6) that MUST be ignored.

    # MS-OVBA 2.4.2.1
    def ContentNormalizedData(self):

        logger.debug("Start production of ContentNormalizedData")
        
        dir_info = self.parsed_dir_stream

        # print("Contents of dir stream:")
        # print(dir_stream)

        Buffer = bytearray()

        reporter = Reporter(Buffer)
        report_buffer = reporter.report

        PROJECTNAME = dir_info['InformationRecord']['NameRecord']
        Buffer.extend(PROJECTNAME['ProjectName']['raw_value'])
        report_buffer("Buffer after PROJECTNAME")

        PROJECTCONSTANTS = dir_info['InformationRecord']['ConstantsRecord']
        Buffer.extend(PROJECTCONSTANTS['Constants']['raw_value'])
        report_buffer("Buffer after PROJECTCONSTANTS")

        PROJECTREFERENCES = dir_info['ReferencesRecord']
        for REFERENCE in PROJECTREFERENCES['ReferenceArray']:

            ReferenceRecord = REFERENCE['ReferenceRecord']

            if ReferenceRecord['Id']['value'] == 0x000D:
                # REFERENCEREGISTERED
                Buffer.append(0x7B)
                report_buffer("Buffer after 0x000D REFERENCEREGISTERED")

            elif ReferenceRecord['Id']['value'] == 0x000E:
                # REFERENCEPROJECT
                logger.error("Handling 0x000E REFERENCEPROJECT")
                ReferenceProject = ReferenceRecord

                TempBuffer = bytearray()
                
                TempBuffer.extend(ReferenceProject['Id']['raw_value'])
                TempBuffer.extend(ReferenceProject['SizeOfLibidAbsolute']['raw_value'])
                TempBuffer.extend(ReferenceProject['LibidAbsolute']['raw_value'])
                TempBuffer.extend(ReferenceProject['SizeOfLibidRelative']['raw_value'])
                TempBuffer.extend(ReferenceProject['LibidRelative']['raw_value'])
                TempBuffer.extend(ReferenceProject['MajorVersion']['raw_value'])
                TempBuffer.extend(ReferenceProject['MinorVersion']['raw_value'])

                CopyIndex = 0
                CopyByte = TempBuffer[CopyIndex]

                # In fact, this may very easily stop to soon, allowing
                # modifying the file without invalidating the signature
                while CopyByte != 0x00:
                    Buffer.append(CopyByte)
                    CopyIndex += 1
                    CopyByte = TempBuffer[CopyIndex]

                report_buffer("Buffer after 0x000E REFERENCEPROJECT")

        PROJECTMODULES = dir_info['ModulesRecord']

        for MODULE in PROJECTMODULES['Modules']:

            ModuleStreamName = MODULE['StreamNameRecord']['StreamNameUnicode']['value']
            logger.debug("Looking for module %s" % ModuleStreamName)
            module_stream_info = self.cbf.find_stream_by_name(ModuleStreamName)
            module_stream = self.cbf.get_stream(module_stream_info.index)

            CompressedContainer = module_stream[MODULE['OffsetRecord']['TextOffset']['value']:]

            Text = decompress_stream(CompressedContainer)

            logger.debug("Module Text: %s (%d bytes)" % (ModuleStreamName, len(Text)))
            logger.debug("Module Text: <%s>" % Text)

            Lines = []
            TextBuffer = bytearray([])
            PreviousChar = b''

            for Char in Text:
                # logger.debug("Char is 0x%02X (%s)" % (Char, chr(Char)))
                if Char == 0x0D or (Char == 0x0A and PreviousChar != 0x0D):
                    logger.debug("Append TextBuffer to Lines: %s" % TextBuffer)
                    Lines.append(TextBuffer)
                    TextBuffer = bytearray([])
                else:
                    if Char != 0x0A:
                        TextBuffer.append(Char)

                PreviousChar = Char

            logger.debug("Append last TextBuffer to Lines: %s" % TextBuffer)
            Lines.append(TextBuffer)
            
            for Line in Lines:
                logger.debug("Line: %s" % Line)
                if not Line.lower().startswith(b'attribute'):
                    Buffer.extend(Line)
                    logger.debug("Added non-attribute Line to Buffer length %d: %s" % (len(Line), Line))

        report_buffer("Final Buffer")

        logger.debug("End production of ContentNormalizedData")

        return Buffer

    # MS-OVBA 2.4.2.2
    def FormsNormalizedData(self):
        logger.debug("Start production of FormsNormalizedData")
        
        ContentBuffer = bytearray()

        project_info = self.parsed_PROJECT_stream

        for property in project_info['ProjectProperties']:
            name = property['name']
            value = property['value']

            if name == 'BaseClass':
                ContentBuffer.extend(self.NormalizeDesignerStorage(value))

        return ContentBuffer

    # MS-OVBA 2.4.2.3 Content Hash
    def ContentHash(self, digest_algorithm):
        ContentBuffer = bytearray()

        # MS-OVBA 2.4.2.1
        ContentNormalizedData = self.ContentNormalizedData()

        logger.info("ContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)
       
        open("NormalizedData.bin", "wb").write(ContentBuffer)
        hash = digest_algorithm(ContentBuffer)
        logger.debug("ContentHash: %s" % hash.hexdigest())
        return hash

    # MS-OVBA 2.4.2.4 Agile Content Hash
    def AgileContentHash(self, digest_algorithm):
        ContentBuffer = bytearray()

        # MS-OVBA 2.4.2.1
        ContentNormalizedData = self.ContentNormalizedData()
        logger.info("ContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)

        # MS-OVBA 2.4.2.2
        FormsNormalizedData = self.FormsNormalizedData()
        logger.info("FormsNormalizedData: %s" % hexlify(FormsNormalizedData))
        ContentBuffer.extend(FormsNormalizedData)
        
        open("AgileNormalizedData.bin", "wb").write(ContentBuffer)
        hash = digest_algorithm(ContentBuffer)
        logger.debug("AgileContentHash: %s" % hash.hexdigest())
        return hash

    # MS-OVBA 2.4.2.5 V3 Content Normalized Data
    def v3_content_normalized_data(self):

        logger.debug("Start production of V3ContentNormalizedData")

        dir_info = self.parsed_dir_stream

        logger.debug("Parsed dir stream: %s" % dir_info)

        Buffer = bytearray()

        reporter = Reporter(Buffer)
        report_buffer = reporter.report

        PROJECTSYSKIND = dir_info['InformationRecord']['SysKindRecord']
        Buffer.extend(PROJECTSYSKIND['Id']['raw_value'])
        Buffer.extend(PROJECTSYSKIND['Size']['raw_value'])
        report_buffer("Buffer after PROJECTSYSKIND")

        PROJECTLCID = dir_info['InformationRecord']['LcidRecord']
        Buffer.extend(PROJECTLCID['Id']['raw_value'])
        Buffer.extend(PROJECTLCID['Size']['raw_value'])
        Buffer.extend(PROJECTLCID['Lcid']['raw_value'])
        report_buffer("Buffer after PROJECTLCID")

        PROJECTLCIDINVOKE = dir_info['InformationRecord']['LcidInvokeRecord']
        Buffer.extend(PROJECTLCIDINVOKE['Id']['raw_value'])
        Buffer.extend(PROJECTLCIDINVOKE['Size']['raw_value'])
        Buffer.extend(PROJECTLCIDINVOKE['LcdInvoke']['raw_value'])
        report_buffer("Buffer after PROJECTLCIDINVOKE")

        PROJECTCODEPAGE = dir_info['InformationRecord']['CodePageRecord']
        Buffer.extend(PROJECTCODEPAGE['Id']['raw_value'])
        Buffer.extend(PROJECTCODEPAGE['Size']['raw_value'])
        report_buffer("Buffer after PROJECTCODEPAGE")

        PROJECTNAME = dir_info['InformationRecord']['NameRecord']
        Buffer.extend(PROJECTNAME['Id']['raw_value'])
        Buffer.extend(PROJECTNAME['SizeOfProjectName']['raw_value'])
        Buffer.extend(PROJECTNAME['ProjectName']['raw_value'])
        report_buffer("Buffer after PROJECTNAME")

        PROJECTDOCSTRING = dir_info['InformationRecord']['DocStringRecord']
        Buffer.extend(PROJECTDOCSTRING['Id']['raw_value'])
        Buffer.extend(PROJECTDOCSTRING['SizeOfDocString']['raw_value'])
        Buffer.extend(PROJECTDOCSTRING['Reserved']['raw_value'])
        Buffer.extend(PROJECTDOCSTRING['SizeOfDocStringUnicode']['raw_value'])
        report_buffer("Buffer after PROJECTDOCSTRING")

        PROJECTHELPFILEPATH = dir_info['InformationRecord']['HelpFilePathRecord']
        Buffer.extend(PROJECTHELPFILEPATH['Id']['raw_value'])
        Buffer.extend(PROJECTHELPFILEPATH['SizeOfHelpFile1']['raw_value'])
        Buffer.extend(PROJECTHELPFILEPATH['Reserved']['raw_value'])
        Buffer.extend(PROJECTHELPFILEPATH['SizeOfHelpFile2']['raw_value'])
        report_buffer("Buffer after PROJECTHELPFILEPATH")

        PROJECTHELPCONTEXT = dir_info['InformationRecord']['HelpContextRecord']
        Buffer.extend(PROJECTHELPCONTEXT['Id']['raw_value'])
        Buffer.extend(PROJECTHELPCONTEXT['Size']['raw_value'])
        report_buffer("Buffer after PROJECTHELPCONTEXT")

        PROJECTLIBFLAGS = dir_info['InformationRecord']['LibFlagsRecord']
        Buffer.extend(PROJECTLIBFLAGS['Id']['raw_value'])
        Buffer.extend(PROJECTLIBFLAGS['Size']['raw_value'])
        Buffer.extend(PROJECTLIBFLAGS['ProjectLibFlags']['raw_value'])
        report_buffer("Buffer after PROJECTLIBFLAGS")

        PROJECTVERSION = dir_info['InformationRecord']['VersionRecord']
        Buffer.extend(PROJECTVERSION['Id']['raw_value'])
        Buffer.extend(PROJECTVERSION['Reserved']['raw_value'])
        Buffer.extend(PROJECTVERSION['VersionMajor']['raw_value'])
        Buffer.extend(PROJECTVERSION['VersionMinor']['raw_value'])
        report_buffer("Buffer after PROJECTVERSION")

        PROJECTCONSTANTS = dir_info['InformationRecord']['ConstantsRecord']
        Buffer.extend(PROJECTCONSTANTS['Id']['raw_value'])
        Buffer.extend(PROJECTCONSTANTS['SizeOfConstants']['raw_value'])
        Buffer.extend(PROJECTCONSTANTS['Constants']['raw_value'])
        Buffer.extend(PROJECTCONSTANTS['Reserved']['raw_value'])
        Buffer.extend(PROJECTCONSTANTS['SizeOfConstantsUnicode']['raw_value'])
        Buffer.extend(PROJECTCONSTANTS['ConstantsUnicode']['raw_value'])
        report_buffer("Buffer after PROJECTCONSTANTS")

        PROJECTREFERENCES = dir_info['ReferencesRecord']
        for REFERENCE in PROJECTREFERENCES['ReferenceArray']:
            REFERENCENAME = REFERENCE['NameRecord']
            Buffer.extend(REFERENCENAME['Id']['raw_value'])
            Buffer.extend(REFERENCENAME['SizeOfName']['raw_value'])
            Buffer.extend(REFERENCENAME['Name']['raw_value'])
            Buffer.extend(REFERENCENAME['Reserved']['raw_value'])
            Buffer.extend(REFERENCENAME['SizeOfNameUnicode']['raw_value'])
            Buffer.extend(REFERENCENAME['NameUnicode']['raw_value'])
            
            ReferenceRecord = REFERENCE['ReferenceRecord']

            if ReferenceRecord['Id']['value'] == 0x002F:
                # REFERENCECONTROL
                ReferenceControl = ReferenceRecord
                Buffer.extend(ReferenceControl['Id']['raw_value'])
                Buffer.extend(ReferenceControl['SizeOfLibidTwiddled']['raw_value'])
                Buffer.extend(ReferenceControl['LibidTwiddled']['raw_value'])
                Buffer.extend(ReferenceControl['Reserved1']['raw_value'])
                Buffer.extend(ReferenceControl['Reserved2']['raw_value'])
            
                if ReferenceControl['NameRecordExtended']:
                    NameRecordExtended = ReferenceControl['NameRecordExtended']
                    Buffer.extend(NameRecordExtended['Id']['raw_value'])
                    Buffer.extend(NameRecordExtended['Size']['raw_value'])
                    Buffer.extend(NameRecordExtended['Name']['raw_value'])

                    # Weird: Not always there?
                    if NameRecordExtended['Reserved']:
                        Buffer.extend(NameRecordExtended['Reserved']['raw_value'])
                        Buffer.extend(NameRecordExtended['SizeOfNameUnicode']['raw_value'])
                        Buffer.extend(NameRecordExtended['NameUnicode']['raw_value'])

                Buffer.extend(ReferenceControl['Reserved3']['raw_value'])
                Buffer.extend(ReferenceControl['SizeOfLibidExtended']['raw_value'])
                Buffer.extend(ReferenceControl['LibidExtended']['raw_value'])
                Buffer.extend(ReferenceControl['Reserved4']['raw_value'])
                Buffer.extend(ReferenceControl['Reserved5']['raw_value'])
                Buffer.extend(ReferenceControl['OriginalTypeLib']['raw_value'])
                Buffer.extend(ReferenceControl['Cookie']['raw_value'])

                report_buffer("Buffer after 0x002F REFERENCECONTROL")
                
            elif ReferenceRecord['Id']['value'] == 0x0033:
                # REFERENCEORIGINAL
                ReferenceOriginal = ReferenceRecord
                Buffer.extend(ReferenceOriginal['Id']['raw_value'])
                Buffer.extend(ReferenceOriginal['SizeOfLibidOriginal']['raw_value'])
                # Buffer.extend(ReferenceOriginal['LibidOriginal']['raw_value'])
                Buffer.extend(self.mbcs_fix_encode(ReferenceOriginal['LibidOriginal']))
                report_buffer("Buffer after 0x0033 REFERENCEORIGINAL")

                
            elif ReferenceRecord['Id']['value'] == 0x000D:
                # REFERENCEREGISTERED
                ReferenceRegistered = ReferenceRecord
                Buffer.extend(ReferenceRegistered['Id']['raw_value'])
                Buffer.extend(ReferenceRegistered['SizeOfLibid']['raw_value'])
                # Buffer.extend(pack('<H', ReferenceRegistered['SizeOfLibid']['value']*2))
                # Buffer.extend(ReferenceRegistered['Libid']['raw_value'])
                # In the samples we have seen, this is not MBCS, but UTF-16
                Buffer.extend(self.mbcs_fix_encode(ReferenceRegistered['Libid']))
                Buffer.extend(ReferenceRegistered['Reserved1']['raw_value'])
                Buffer.extend(ReferenceRegistered['Reserved2']['raw_value'])
                report_buffer("Buffer after 0x000D REFERENCEREGISTERED")

            elif ReferenceRecord['Id']['value'] == 0x000E:
                # REFERENCEPROJECT
                logger.error("Handling 0x000E REFERENCEPROJECT")
                ReferenceProject = ReferenceRecord
                Buffer.extend(ReferenceProject['Id']['raw_value'])
                Buffer.extend(ReferenceProject['SizeOfLibidAbsolute']['raw_value'])
                # Buffer.extend(ReferenceProject['LibidAbsolute']['raw_value'])
                Buffer.extend(self.mbcs_fix_encode(ReferenceProject['LibidAbsolute']))
                Buffer.extend(ReferenceProject['SizeOfLibidRelative']['raw_value'])
                Buffer.extend(ReferenceProject['LibidRelative']['raw_value'])
                Buffer.extend(ReferenceProject['MajorVersion']['raw_value'])
                Buffer.extend(ReferenceProject['MinorVersion']['raw_value'])
                report_buffer("Buffer after 0x000E REFERENCEPROJECT")

            else:
                report_buffer("Buffer after weird reference 0x%04x" % ReferenceRecord['Id']['value'])

        PROJECTMODULES = dir_info['ModulesRecord']
        Buffer.extend(PROJECTMODULES['Id']['raw_value'])
        Buffer.extend(PROJECTMODULES['Size']['raw_value'])
        PROJECTCOOKIE = PROJECTMODULES['ProjectCookieRecord']
        Buffer.extend(PROJECTCOOKIE['Id']['raw_value'])
        Buffer.extend(PROJECTCOOKIE['Size']['raw_value'])

        report_buffer("Buffer after PROJECTMODULES start")

        DefaultAttributes = [
            b"attribute vb_base = \"0{00020820-0000-0000-c000-000000000046}\"",
            b"attribute vb_globalnamespace = false",
            b"attribute vb_creatable = false",
            b"attribute vb_predeclaredid = true",
            b"attribute vb_exposed = true",
            b"attribute vb_templatederived = false",
            b"attribute vb_customizable = true"
        ]

        for MODULE in PROJECTMODULES['Modules']:
            # MODULE
            if MODULE['TypeRecord']['Id']['value'] == 0x21:
                Buffer.extend(MODULE['TypeRecord']['Id']['raw_value'])
                Buffer.extend(MODULE['TypeRecord']['Reserved']['raw_value'])
            if MODULE['ReadOnlyRecord']:
                Buffer.extend(MODULE['ReadOnlyRecord']['Id']['raw_value'])
                Buffer.extend(MODULE['ReadOnlyRecord']['Reserved']['raw_value'])
            if MODULE['PrivateRecord']:
                Buffer.extend(MODULE['PrivateRecord']['Id']['raw_value'])
                Buffer.extend(MODULE['PrivateRecord']['Reserved']['raw_value'])

            ModuleStreamName = MODULE['StreamNameRecord']['StreamNameUnicode']['value']
            logger.debug("Looking for module %s" % ModuleStreamName)
            module_stream_info = self.cbf.find_stream_by_name(ModuleStreamName)
            module_stream = self.cbf.get_stream(module_stream_info.index)

            CompressedContainer = module_stream[MODULE['OffsetRecord']['TextOffset']['value']:]

            Text = decompress_stream(CompressedContainer)

            logger.debug("Module Text: %s (%d bytes)" % (ModuleStreamName, len(Text)))
            logger.debug("Module Text: <%s>" % Text)
            
            open("%s.bin" % ModuleStreamName, 'wb').write(Text)

            Lines = []
            TextBuffer = bytearray([])
            PreviousChar = b''

            for Char in Text:
                # logger.debug("Char is 0x%02X (%s)" % (Char, chr(Char)))
                if Char == 0x0D or (Char == 0x0A and PreviousChar != 0x0D):
                    logger.debug("Append TextBuffer to Lines: %s" % TextBuffer)
                    Lines.append(TextBuffer)
                    TextBuffer = bytearray([])
                elif Char == 0x0A and PreviousChar == 0x0D:
                    continue
                else:
                    TextBuffer.append(Char)
                PreviousChar = Char
            logger.debug("Append last TextBuffer to Lines: %s" % TextBuffer)
            if len(TextBuffer) > 0:
                Lines.append(TextBuffer)

            HashModuleNameFlag = False
            for Line in Lines:
                logger.debug("Line: %s" % Line)
                if not Line.lower().startswith(b'attribute'):
                    HashModuleNameFlag = True
                    Buffer.extend(Line)
                    Buffer.append(0x0A)
                    logger.debug("Added non-attribute Line plus LF to Buffer length %d: %s" % (len(Line), Line))
                elif Line.lower().startswith(b'attribute vb_name = '):
                    continue
                elif Line.lower() not in DefaultAttributes:
                    HashModuleNameFlag = True
                    Buffer.extend(Line)
                    Buffer.append(0x0A)
                    logger.debug("Added non-default attribute Line plus LF to Buffer length %d: %s" % (len(Line), Line))

            if HashModuleNameFlag:
                if MODULE['NameUnicodeRecord']['ModuleNameUnicode']['value']:
                    Buffer.extend(MODULE['NameUnicodeRecord']['ModuleNameUnicode']['raw_value'])
                elif MODULE['NameRecord']['ModuleName']['value']:
                    # Buffer.extend(MODULE['NameRecord']['ModuleName']['raw_value'])
                    Buffer.extend(MODULE['NameRecord']['ModuleName']['value'].encode('UTF-16-LE'))
                Buffer.append(0x0A)

            report_buffer("Buffer after module")

        Buffer.extend(dir_info['Terminator']['raw_value'])
        Buffer.extend(dir_info['Reserved']['raw_value'])

        report_buffer("Final Buffer")

        logger.debug("End production of V3ContentNormalizedData")

        return Buffer

    # MS-OVBA 2.3.1 PROJECT Stream: Project Information

    # VBAPROJECTText    = ProjectProperties NWLN 
    #                     HostExtenders 
    #                     [NWLN ProjectWorkspace]
    #
    # ProjectProperties  = ProjectId
    #                     *ProjectItem 
    #                     [ProjectHelpFile] 
    #                     [ProjectExeName32] 
    #                      ProjectName
    #                      ProjectHelpId 
    #                     [ProjectDescription] 
    #                     [ProjectVersionCompat32] 
    #                      ProjectProtectionState
    #                      ProjectPassword
    #                      ProjectVisibilityState
  
    # ProjectItem        = ( ProjectModule /
    #                        ProjectPackage ) NWLN
    
    # ID="{4EC0B064-D078-46B1-A4CC-19D69D2B80AB}"
    # Document=ThisWorkbook/&H00000000
    # Document=Hoja1/&H00000000
    # Document=Hoja2/&H00000000
    # Document=Hoja3/&H00000000
    # Name="VBAProject"
    # HelpContextID="0"
    # VersionCompatible32="393222000"
    # CMG="696B865E8A5E8A5E8A5E8A"
    # DPB="DDDF32BAD22FD32FD32F"
    # GC="5153BE43BF43BFBC"

    # [Host Extender Info]
    # &H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000

    # [Workspace]
    # ThisWorkbook=0, 0, 0, 0, C
    # Hoja1=0, 0, 0, 0, C
    # Hoja2=60, 35, 1060, 567, Z
    # Hoja3=41, 379, 1041, 911, C

    def parse_project_stream(self, project_stream):

        logger.info("Start of parse_project_stream")
        logger.debug("Project stream: %s" % project_stream)
        info = {
            'ProjectProperties': [],
            'HostExtenders': [],
            'ProjectWorkspace': OrderedDict(),
        }
        lines = project_stream.split(b'\r\n')

        lineno = 0
        while lineno < len(lines):
            line = lines[lineno]
            if len(line) == 0 or line[0] == b' ':
                lineno += 1
                continue
            if line[0] == ord('['):
                logger.debug("Break from ProjectProperties, line: %s" % line)
                break
            logger.debug("PS Line: %d %s" % (len(line), line))
            name, value = line.split(b'=')
            name = name.strip(b'"')
            value = value.strip(b'"')
            logger.debug("<%s>=<%s>" % (name, value))
            info['ProjectProperties'].append({
                'name': name,
                'value': value,
            })
            lineno += 1

        logger.debug("ProjectProperties: %s" % info['ProjectProperties'])

        if line == b'[Host Extender Info]':
            logger.debug('[Host Extender Info]')
            lineno += 1
            # According to the syntax in 2.3.1.18, there can be more
            # than one HostExtenderRef, but it is unclear how to
            # handle more than one later in ProjectNormalizedData
            while lineno < len(lines):
                line = lines[lineno]
                if len(line) == 0 or line[0] == ord(' '):
                    lineno += 1
                    continue
                if line[0] == ord('['):
                    logger.debug("Break from Host Extender Info, line: %s" % line)
                    break
                logger.debug("PS HEI Line: %d %s" % (len(line), line))
                info['HostExtenders'].append(line)
                lineno += 1

        if line == b'[Workspace]':
            logger.debug('Handling [Workspace]')
            lineno += 1
            while lineno < len(lines):
                line = lines[lineno]
                if len(line) == 0 or line[0] == b' ':
                    lineno += 1
                    continue

                name, value = line.split(b'=')
                logger.debug("<%s>=<%s>" % (name, value))
                info['ProjectWorkspace'][name] = value
                lineno += 1

        logger.info("End of parse_project_stream")
        return info

    # 2.4.2.6 Project Normalized Data
    def ProjectNormalizedData(self):

        logger.debug("Starting ProjectNormalizeData")

        project_info = self.parsed_PROJECT_stream

        Buffer = bytearray()
 
        name_map = {
            b'ProjectId': b'ID',			# Skipped
            b'ProjectDocModule': b'Document',		# Skipped
            b'ProjectStdModule': b'Module',
            b'ProjectClassModule': b'Class',
            b'ProjectDesignerModule': b'BaseClass',	# Special
            b'ProjectPackage': b'Package',
            b'ProjectHelpFile': b'HelpFile',
            b'ProjectExeName32': b'ExeName32',
            b'ProjectName': b'Name',
            b'ProjectHelpId': b'HelpContextID',
            b'ProjectDescription': b'Description',
            b'ProjectVersionCompat32': b'VersionCompatible32',
            b'ProjectProtectionState': b'CMG',		# Skipped
            b'ProjectPassword': b'DPB',			# Skipped
            b'ProjectVisibilityState': b'GC',		# Skipped
        }

        reverse_name_map = {name_map[x]: x for x in name_map.keys()}

        for property in project_info['ProjectProperties']:
            name = property['name']
            value = property['value']
            logger.debug("Property: %s <%s>=<%s>" % (reverse_name_map.get(name, b'unkn'), name, value))
            if name == name_map[b'ProjectDesignerModule']:
                logger.debug("Property %s (%s): %s" % (name, reverse_name_map[name], value))
                # ProjectDesignerModule
                Buffer.extend(self.NormalizeDesignerStorage(value))
            if name not in [name_map[x] for x in [
                    b'ProjectId',
                    b'ProjectDocModule',
                    b'ProjectProtectionState',
                    b'ProjectPassword',
                    b'ProjectVisibilityState',
                    # b'ProjectPackage',
            ]]:
                logger.debug("Included %s (%s): %s" % (name, reverse_name_map.get(name, 'unkn'), value))
                Buffer.extend(name)
                Buffer.extend(value)
            else:
                logger.debug("Excluded %s (%s): %s" % (name, reverse_name_map[name], value))

        if project_info['HostExtenders']:
            logger.debug("Procesando HostExtenders")
            Buffer.extend(b'Host Extender Info')
            # Buffer.extend(project_info['HostExtenders'][0])
            for extender in project_info['HostExtenders']:
                logger.debug("HostExtender: %s" % extender)
                Buffer.extend(extender)

        logger.debug("ProjectNormalizedData: %s" % Buffer)
        logger.info("Finished ProjectNormalizeData")

        return Buffer

    # MS-OVBA 2.4.2.7 V3 Content Hash
    def V3ContentHash(self, digest_algorithm):
        ContentBuffer = bytearray()

        # 2.4.2.5 V3 Content Normalized Data
        V3ContentNormalizedData = self.v3_content_normalized_data()
        logger.info("V3ContentNormalizedData: %s" % hexlify(V3ContentNormalizedData))
        ContentBuffer.extend(V3ContentNormalizedData)

        # 2.4.2.6 Project Normalized Data
        ProjectNormalizedData = self.ProjectNormalizedData()
        logger.debug("ProjectNormalizedData: %s" % hexlify(ProjectNormalizedData))
        ContentBuffer.extend(ProjectNormalizedData)

        open("V3NormalizedData.bin", "wb").write(ContentBuffer)
        # ContentBuffer.extend(b'\x0D\x0A')
        hash = digest_algorithm(ContentBuffer)
        logger.debug("computedHash: %s" % hash.hexdigest())

        return hash

        
