
# Handle an Open Container Conventions file

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
        
        for e in media_types.iterfind('.//{%s}' % ns + 'Override'):
            ct = e.get('ContentType')
            ext = e.get('Extension')
            self._default_media_types[ext] = ct

        for e in media_types.iterfind('.//{%s}' % ns + 'Override'):
            ct = e.get('ContentType')
            pn = e.get('PartName')
            self._media_types[pn] = ct

    def part_media_type(self, part_name):
        if part_name in self._media_types:
            return self._media_types[part_name]

        dotpos = part_name.rfind('.')
        ext = part_name[dotpos+1]
        if ext in self._default_media_types:
            return self._default_media_types[ext]
        else:
            logger.error("Unknown media type for %s" % part_name)
        
    def load_contents(self):
        self.parts = dict()
        for pn in self.zipfile.infolist():
            part_name = pn.filename
            try:
                pn_type = self.part_media_type(part_name)
            except KeyError:
                logger.info("%s file found, but not in [Content_Types].xml" % part_name)
                continue
            logger.debug("%s: %s" % (ct, part_name))
            self.parts[part_name] = pn_type

    def part_media_type(self, part_name):
        return self.parts[part_name]

    def find(self, media_type):
        results = []
        for pn, pn_type in self.parts.items():
            if pn_type == media_type:
                results.append(pn)
        return results

    def find_related(self, part_name):
        raise Exception
