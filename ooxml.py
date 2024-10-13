
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
            self.vbaProjectFileName = None
        elif len(parts) == 1:
            self.vbaProjectFileName = parts[0]
        else:
            logger.error("More than one part with media type application/vnd.ms-office.vbaProject - unsupported")
            self.vbaProjectFileName = None

        self.vbaProjectSignatureFileName = None
        self.vbaProjectSignatureAgileFileName = None
        self.vbaProjectSignatureV3FileName = None

        if self.vbaProjectFileName:
            related = self.opc.find_related(self.vbaProjectFileName)
            self.vbaProjectSignatureFileName = related.get('vbaProjectSignature', None)
            self.vbaProjectSignatureAgileFileName = related.get('vbaProjectSignatureAgile', None)
            self.vbaProjectSignatureV3FileName = related.get('vbaProjectSignatureV3', None)

    @property
    def has_macros(self):
        return True if self.vbaProjectFileName else False

    @property
    def has_signed_macros_legacy(self):
        if self.has_macros:
            if self.vbaProjectSignatureFileName:
                return True
        return False

    @property
    def has_signed_macros_agile(self):
        if self.has_macros:
            if self.vbaProjectSignatureAgileFileName:
                return True
        return False

    @property
    def has_signed_macros_v3(self):
        if self.has_macros:
            if self.vbaProjectSignatureV3FileName:
                return True
        return False

    @property
    def has_signed_macros(self):
        if self.has_signed_macros_legacy or self.has_signed_macros_agile or has_signed_macros_v3:
                return True
        return False
