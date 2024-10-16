
# Handle an Open Container Conventions file
# TBC: part_names must be matched case-insensitively
# OK Part names start with /
# Zip members don¡t
import logging
logger = logging.getLogger(__name__)

import zipfile
from io import BytesIO
from lxml import etree

class OPC:

    def __init__(self, input=None):

        self.file = None
        self.zipfile = None
        self._default_media_types = dict()
        self._media_types = dict()
        self.parts = dict()
        
        if input:
            if hasattr(input, 'read'):
                self.file = input
            elif isinstance(input, bytes):
                self.file = BytesIO(input)
            elif isinstance(input, str):
                self.file= open(input, 'rb')
            else:
                raise ValueError("Input is unsupported %s" % type(input))
            self.parse()
        else:
            self.file = None

    def parse(self):

        # We only support OPC as a ZIP file (the standard
        try:
            self.zipfile = zipfile.ZipFile(self.file)
        except zipfile.BadZipFile:
            raise ValueError("Data is not a ZIP file or it is corrupted, unsupported format")
        self.load_media_types()
        self.load_contents()

    def load_media_types(self):
        media_types_location =  '[Content_Types].xml'
        # Actually, this location may be a folder whose files
        # need to be loaded. Unclear if this is ever used. TBC.
        mt = self.zipfile.open(media_types_location)
        media_types_xml = etree.parse(mt)
        media_types = media_types_xml.getroot()

        # lxml qualifies names with full URIs, so we need to match
        # against the full values
        ns = 'http://schemas.openxmlformats.org/package/2006/content-types'
        
        for e in media_types.iterfind('.//{%s}' % ns + 'Default'):
            ct = e.get('ContentType')
            ext = e.get('Extension')
            logger.debug("Extension %s is %s" % (ext, ct))
            self._default_media_types[ext] = ct

        for e in media_types.iterfind('.//{%s}' % ns + 'Override'):
            ct = e.get('ContentType')
            pn = e.get('PartName')
            # Part names come with an initial /
            logger.debug("Part name %s is %s" % (pn, ct))
            self._media_types[pn] = ct

    def part_media_type(self, part_name):
        if not part_name.startswith('/'):
            part_name = '/' + part_name
        if part_name in self._media_types:
            return self._media_types[part_name]

        logger.debug("{} was not explicitly mentioned in [Content_Types].xml".format(part_name))
        dotpos = part_name.rfind('.')
        ext = part_name[dotpos+1:]
        if ext in self._default_media_types:
            return self._default_media_types[ext]
        else:
            logger.error("Unknown media type for %s" % part_name)
            return None
            
    def load_contents(self):
        self.parts = dict()
        for pn in self.zipfile.infolist():
            part_name = pn.filename
            pn_type = self.part_media_type(part_name)
            self.parts[part_name] = pn_type

    def find(self, media_type):
        results = []
        logger.debug("Finding entries with media type {} in {} parts".format(media_type, len(self.parts)))
        for pn, pn_type in self.parts.items():
            logger.debug("Matching against part media type {}".format(pn_type))
            if pn_type == media_type:
                logger.debug("Entry {} matched media type {}".format(pn, media_type))
                results.append(pn)
        else:
            logger.debug("No entry matched media type {}".format(media_type))
            
        return results

    def find_related(self, part_name):
        # The Part Relationships part is constructed from the part name
        if not part_name.startswith('/'):
            part_name = '/' + part_name
        barpos = part_name.rfind('/')
        base = part_name[0:barpos]
        rels_part_name = base + '/_rels' + part_name[barpos:] + '.rels'
        logger.debug("Relationships part for {} is {}".format(part_name, rels_part_name))

        related = dict()

        try:
            rt = self.zipfile.open(rels_part_name[1:])
        except KeyError:
            logger.debug("No rels file for {}".format(part_name))
            return related

        rt_xml = etree.parse(rt)
        rels = rt_xml.getroot()

        # lxml qualifies names with full URIs, so we need to match
        # against the full values
        ns = 'http://schemas.openxmlformats.org/package/2006/relationships'

        for e in rels.iterfind('.//{%s}' % ns + 'Relationship'):
            id = e.get('Id')
            target = e.get('Target')
            if not target.startswith('/'):
                target = base + '/' + target
            ptype = e.get('Type')
            if ptype == "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature":
                kind = "vbaProjectSignature"
            elif ptype == "http://schemas.microsoft.com/office/2014/relationships/vbaProjectSignatureAgile":
                kind = "vbaProjectSignatureAgile"
            elif ptype == "http://schemas.microsoft.com/office/2020/07/relationships/vbaProjectSignatureV3":
                kind = "vbaProjectSignatureV3"
            else:
                logger.error("Related {} {} for {} unknown".format(target, ptype, part_name))
                continue
            logger.debug("Related {} {} for {}".format(target, kind, part_name))
            related[kind] = target
                    
        return related

    def read_part(self, part_name):
        pname = part_name[1:] if part_name.startswith('/') else part_name
        f = self.zipfile.open(pname)
        return f.read()
