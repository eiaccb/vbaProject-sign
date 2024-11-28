
# Handle an Open Container Conventions file
# TBC: part_names must be matched case-insensitively
# OK Part names start with /
# Zip members don¡t
import logging
logger = logging.getLogger(__name__)

import os
import zipfile
from io import BytesIO
import tempfile
import re
from lxml import etree

class OPC:

    def __init__(self, input=None, mode='r', extension='.zip'):

        self.file = None
        self.path = None
        self.original_path = None
        self.mode = mode
        self.extension = extension
        self.zipfile = None
        self._default_media_types = dict()
        self._media_types = dict()
        self.parts = dict()
        self.changes_pending = []
        
        # For now, we will try not to modify in place
        # In any case, we need an actual file to make changes
        # Apparently`python zipfile cannot do the whole process
        # in memory
        if input:
            logger.debug("Input is {}".format(input))
            if hasattr(input, 'read'):
                self.file = input
            elif isinstance(input, bytes):
                self.file = BytesIO(input)
            elif isinstance(input, str):
                self.original_path = input
                basename, extension = os.path.splitext(input)
                self.extension = extension
                self.path = self.original_path
                self.file= open(self.path, 'rb')
            else:
                raise ValueError("Input is unsupported %s" % type(input))
            if self.mode != 'r':
                original_file = self.file
                self.file = tempfile.NamedTemporaryFile(
                    suffix=self.extension, delete=False)
                self.path = self.file.name
                logger.debug("Temporary file is {}".format(self.path))
                # Chunk it in the future
                self.file.write(original_file.read())
                self.file.seek(0)
            self.parse()
        else:
            self.file = None

    def parse(self):

        # We only support OPC as a ZIP file (the standard
        try:
            self.zipfile = zipfile.ZipFile(
                self.file,
                compression=zipfile.ZIP_DEFLATED,
                mode=self.mode)
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

    def update_signatures(self, sigs, output_filename):
        logger.debug("In update_signatures")
        real_sigs = []
        for s in sigs:
            kind, sig, part_name, mime_type = s
            logger.debug("sig: {}, {}".format(kind, part_name))
            parts = self.find(mime_type)
            if len(parts) == 1:
                real_sigs.append((kind, sig, parts[0], mime_type))
            else:
                real_sigs.append(s)

        types = {
            1: 'http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature',
            2: 'http://schemas.microsoft.com/office/2014/relationships/vbaProjectSignatureAgile',
            3: 'http://schemas.microsoft.com/office/2020/07/relationships/vbaProjectSignatureV3',
        }
        related = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        related += '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        for s in sorted(real_sigs, key=lambda x: -x[0].value):
            kind, sig, part_name, mime_type = s
            pos = part_name.index('/')
            target = part_name[pos+1:]
            related += '<Relationship Id="rId{}" Target="{}" Type="{}"/>'.format(kind.value, target, types[kind.value])
        related += '</Relationships>'

        parts = self.find('application/vnd.ms-office.vbaProject')
        if len(parts) != 1:
            raise NotimplementedError
        vbaProjectPath = parts[0]
        pos = vbaProjectPath.rfind('/')
        relatedPath = vbaProjectPath[0:pos] + '/_rels' + vbaProjectPath[pos:] + '.rels'

        media_types_location =  '[Content_Types].xml'
        mtf = self.zipfile.open(media_types_location, mode='r')
        media_types = mtf.read()
        mtf.close()
        pos = re.search(rb'<Override\s+ContentType="application/vnd.ms-office.vbaProject"', media_types)
        if pos:
            pos = media_types.find('<Override ')
        if not pos or pos <0:
            pos = media_types.find(b'</Types>')

        sigs_by_partname = dict()
        insertion = b''
        for s in sorted(real_sigs, key=lambda x: x[0].value):
            kind, sig, part_name, mime_type = s
            sigs_by_partname[part_name] = s
            insertion += ('<Override ContentType="{}" PartName="/{}"/>'.format(mime_type, part_name)).encode('ascii')
        media_types = media_types[0:pos] + insertion + media_types[pos:]

        zf = zipfile.ZipFile(output_filename, mode='w', compression=zipfile.ZIP_DEFLATED)
        related_seen = False
        for zi in self.zipfile.infolist():
            logger.debug("Testing {}".format(zi.filename))
            if zi.filename in sigs_by_partname:
                logger.debug("Replacing {}".format(zi.filename))
                contents = sigs_by_partname[zi.filename][1]
                del sigs_by_partname[zi.filename]
            elif zi.filename == media_types_location:
                logger.debug("Replacing [Content_Types].xml")
                contents = media_types
            elif zi.filename == relatedPath:
                logger.debug("Replacing {}".format(relatedPath))
                related_seen = True
                contents = related
            else:
                logger.debug("Did not match anything {}".format(zi.filename))
                with self.zipfile.open(zi.filename) as f:
                    contents = f.read()
            zf.writestr(zi.filename, contents)
        if not related_seen:
            zf.writestr(relatedPath, related)
        for info in sigs_by_partname.values():
            kind, sig, part_name, mime_type = info
            logger.debug("Adding to new zip {}".format(part_name))
            zf.writestr(part_name, sig)

        zf.close()
        
    def update_part(self, part_name, contents):
        self.changes_pending.append(('U', part_name, contents, None))

    def add_part(self, part_name, mime_type, contents):
        self.changes_pending.append(('A', part_name, contents, mime_type))

    def updated_file(self, filename):
        
        # for c in self.changes_pending:
        
        files = dict()
        for zi in self.zipfile.infolist():
            files[zi.filename] = zi

        
        
        self.zipfile.writestr(part_name, contents)
        # This should be done better and more robustly
        new_val = ('<Override ContentType="{}" PartName="/{}"/>'.format(mime_type, part_name)).encode('ascii')
        media_types_location =  '[Content_Types].xml'
        mtf = self.zipfile.open(media_types_location, mode='r')
        media_types = mtf.read()
        mtf.close()
        pos = media_types.find(b'</Types>')
        new_media_types = media_types[0:pos] + new_val + media_types[pos:]
        mtf = self.zipfile.open(media_types_location, mode='w')
        mtf.write(new_media_types)
        mtf.close()

    def save(self, output_filename):
        self.zipfile.close()
        fin = open(self.path, 'rb')
        fout = open(output_filename, 'wb')
        fout.write(fin.read())
        fin.close()
        fout.close()
        
