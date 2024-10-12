
# Handle an MS Office file of the Office OpenXML variety

import logging
logger = logging.getLogger(__name__)

from opc import OPC

class OpenXML:

    @classmethod
    def __init__(self, input=None):

        self.opc = OPC(input)

        parts = self.opc.find('application/vnd.ms-office.vbaProject')
        logging.debug("{} vbaProject part(s) found".format(len(parts)))
        if len(parts) == 0:
            self.vbaProject = None
        elif len(parts) == 1:
            self.vbaProject = parts[0]
        else:
            logger.error("More than one part with media type application/vnd.ms-office.vbaProject - unsupported")
            self.vbaProject = None

        self.vbaProjectSignature = None
        self.vbaProjectSignatureAgile = None
        self.vbaProjectSignatureV3 = None

        if self.vbaProject:
            related = self.opc.find_related(self.vbaProject)
            for pn in related:
                pn_type = self.opc.part_media_type(pn)

                if pn_type == 'application/vnd.ms-office.vbaProjectSignature':
                    self.vbaProjectSignature = pn
                elif pn_type == 'application/vnd.ms-office.vbaProjectSignatureAgile':
                    self.vbaProjectSignatureAgile = pn
                elif pn_type == 'application/vnd.ms-office.vbaProjectSignatureV3':
                    self.vbaProjectSignatureV3 = pn
                else:
                    logger.debug("Related part %s has unhandled type %s" % (pn, pn_type))

    @property
    def has_macros(self):
        return True if self.vbaProject else False

    @property
    def has_signed_macros_legacy(self):
        if self.has_macros:
            if self.vbaProjectSignature:
                return True
        return False

    @property
    def has_signed_macros_agile(self):
        if self.has_macros:
            if self.vbaProjectSignatureAgile:
                return True
        return False

    @property
    def has_signed_macros_v3(self):
        if self.has_macros:
            if self.vbaProjectSignatureV3:
                return True
        return False

    @property
    def has_signed_macros(self):
        if self.has_signed_macros_legacy or self.has_signed_macros_agile or has_signed_macros_v3:
                return True
        return False
