
# Handle an MS Office file of the Office OpenXML variety

import logging
logger = logging.getLogger(__name__)

from binascii import hexlify

from opc import OPC
from vbaProject import vbaProject
from signature import VbaProjectSignature, SignatureKind, VbaProjectSignatureBuilder

class OpenXML:

    @classmethod
    def __init__(self, input=None):

        self.opc = OPC(input)

        parts = self.opc.find('application/vnd.ms-office.vbaProject')
        logging.debug("{} vbaProject part(s) found".format(len(parts)))
        if len(parts) == 0:
            self.vbaProjectPartName = None
        elif len(parts) == 1:
            self.vbaProjectPartName = parts[0]
            logger.debug("vbaProject is part name {}".format(self.vbaProjectPartName))
        else:
            logger.error("More than one part with media type application/vnd.ms-office.vbaProject - unsupported")
            self.vbaProjectPartName = None

        self.vbaProject = None
        self.vbaProjectSignatures = dict()

        if self.vbaProjectPartName:
            data = self.opc.read_part(self.vbaProjectPartName)
            self.vbaProject = vbaProject.parse(data)
            related = self.opc.find_related(self.vbaProjectPartName)

            part_name = related.get('vbaProjectSignature', None)
            if part_name:
                part = self.opc.read_part(part_name)
                kind = SignatureKind.LEGACY
                self.vbaProjectSignatures[kind] = VbaProjectSignature.parse(self, kind, part_name, part)

            part_name = related.get('vbaProjectSignatureAgile', None)
            if part_name:
                part = self.opc.read_part(part_name)
                kind = SignatureKind.AGILE
                self.vbaProjectSignatures[kind] = VbaProjectSignature.parse(self, kind, part_name, part)

            part_name = related.get('vbaProjectSignatureV3', None)
            if part_name:
                part = self.opc.read_part(part_name)
                kind = SignatureKind.V3
                self.vbaProjectSignatures[kind] = VbaProjectSignature.parse(self, kind, part_name, part)

    @property
    def has_macros(self):
        return True if self.vbaProjectPartName else False

    @property
    def has_signed_macros_legacy(self):
        if self.has_macros:
            if SignatureKind.LEGACY in self.vbaProjectSignatures:
                return True
        return False

    @property
    def has_signed_macros_agile(self):
        if self.has_macros:
            if SignatureKind.AGILE in self.vbaProjectSignatures:
                return True
        return False

    @property
    def has_signed_macros_v3(self):
        if self.has_macros:
            if SignatureKind.V3 in self.vbaProjectSignatures:
                return True
        return False

    @property
    def has_signed_macros(self):
        if len(self.vbaProjectSignatures) > 0:
            return True
        return False

    def get_signature(self, kind):
        if kind in self.vbaProjectSignatures:
            return self.vbaProjectSignatures[kind]
        else:
            raise KeyError("Project does not contain signature of kind {}".format(kind))

    def contentHash(self, signatureClass, digestAlgorithmOID):
        hash =  signatureClass.contentHash(self.vbaProject, digestAlgorithmOID)
        return hash

    def verify_signatures(self):
        verified = True
        for signature_kind, signature in self.vbaProjectSignatures.items():
            # Hash the signature was computed for
            signatureHash = signature.signatureHash
            # Hash of the actual contents computed as needed by this
            # signature method
            targetHash = self.contentHash(signature, signature.digestAlgorithmOID).digest()
            if signatureHash != targetHash:
                logger.debug("Hash mismatch in signature type {}:".format(signature.kind))
                logger.debug("In signature: %s" % hexlify(signatureHash))
                logger.debug("Computed:     %s" % hexlify(targetHash))
                verified = False
            else:
                logger.debug("Hash match in signature type {}:".format(signature.kind))

        return verified
            
    def sign_macros(self, certificates, signer_engine):
        for kind in SignatureKind.choices():
            sig_cls = VbaProjectSignature.get_class(kind)
            builder = VbaProjectSignatureBuilder(
                kind
            ).set_vbaProject(
                self.vbaProject
            ).set_certificates(
                certificates
            )

            sig = builder.sign(signer_engine)
            self.vbaProjectSignatures[kind] = sig

    #def save(self, output_filename):
    # Fill OPC data and write
        
