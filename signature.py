
# Bring signature code from original OpenXML.py

# Formats in [MS-OSHARED] https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/f80ee18c-d72f-4c3c-9ea5-a56f396322e0
# Handle signatures

# Handle the format in [MS-OSHARED] 2.3.2.1 DigSigInfoSerialized
# Véase https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/30a00273-dbee-422f-b488-f4b8430ae046

# cbSignature (4 bytes): An unsigned integer that specifies the size of the
# pbSignatureBuffer field in bytes.

# signatureOffset (4 bytes): An unsigned integer that specifies the offset
# of the pbSignatureBuffer field relative to the beginning of this
# structure’s parent DigSigBlob (section 2.3.2.2); or if the parent is
# a WordSigBlob (section 2.3.2.3), the offset is relative to the beginning
# of the parent’s cbSigInfo field.

# cbSigningCertStore (4 bytes): An unsigned integer that specifies the
# size of the pbSigningCertStoreBuffer field in bytes.

# certStoreOffset (4 bytes): An unsigned integer that specifies the
# offset of the pbSigningCertStoreBuffer field relative to the start
# of this structure’s parent DigSigBlob (section 2.3.2.2); or if the
# parent is a WordSigBlob (section 2.3.2.3), the offset is relative to
# the start of the parent’s cbSigInfo field.

# cbProjectName (4 bytes): An unsigned integer that specifies the
# count in bytes of the rgchProjectNameBuffer field, not including the
# null-terminating character. MUST be 0x00000000.

# projectNameOffset (4 bytes): An unsigned integer that specifies the
# offset of the rgchProjectNameBuffer field relative to the beginning
# of this structure’s parent DigSigBlob (section 2.3.2.2); or if the
# parent is a WordSigBlob (section 2.3.2.3), the offset is relative to
# the beginning of the parent’s cbSigInfo field.

# fTimestamp (4 bytes): This field is reserved and MUST be
# 0x00000000. MUST ignore on reading.

# cbTimestampUrl (4 bytes): An unsigned integer that specifies the
# count in bytes of the rgchTimestampBuffer field, not including the
# null-terminating character. MUST be 0x00000000.

# timestampUrlOffset (4 bytes): An unsigned integer that specifies the
# offset of the rgchTimestampBuffer field relative to the beginning of
# this structure’s parent DigSigBlob (section 2.3.2.2); or if the
# parent is a WordSigBlob (section 2.3.2.3), the offset is relative to
# the beginning of the parent’s cbSigInfo field.

# pbSignatureBuffer (variable): An array of bytes that specifies the
# VBA Digital Signature (section 2.3.2.4) of the VBA project.

# pbSigningCertStoreBuffer (variable): A VBASigSerializedCertStore
# structure (section 2.3.2.5.5) containing the public digital
# certificate information of the certificate used to create the
# digital signature.

# rgchProjectNameBuffer (variable): A null-terminated array of Unicode
# characters. The field is reserved and MUST be a single null Unicode
# character (0x0000).

# rgchTimestampBuffer (variable): A null-terminated array of Unicode
# characters. The field is reserved and MUST be a single null Unicode
# character (0x0000).

import logging
logger = logging.getLogger(__name__)

from struct import pack, unpack
from binascii import hexlify
import hashlib

import pkcs7

def oid2hashlib(digestAlgorithm):
    oid = digestAlgorithm.algorithm.dotted_string
    if oid == '1.2.840.113549.2.5':
        return hashlib.md5
    elif oid == '2.16.840.1.101.3.4.2.1':
        return hashlib.sha256
    elif oid == '2.16.840.1.101.3.4.2.3':
        return hashlib.sha512
    else:
        raise ValueError('Unknown algorithm %s' % digestAlgorithm)

# [MS-OSHARED] 2.3.2.1 DigSigInfoSerialized

# Notice that notionally, a DigSigInfoSerialized is considered part
# of an enclosing structure and the offsets in DigSigInfoSerialized
# must be understood relative to that strucuture. So that we can
# reuse this implementation, we ask for the offset of DigSigInfoSerialized
# in the enclosing structure so that we can adjust the values.

class DigSigInfoSerialized:

    def __init__(self, data=None, offset=0):

        if data:
            logger.debug("DigSigInfoSerialized: " + str(hexlify(data[:128])))
            self._initialized = True
            self.offset = offset
            (
                cbSignature,
                signatureOffset,
                cbSigningCertStore,
                certStoreOffset,
                cbProjectName,
                projectNameOffset,
                fTimestamp,
                cbTimestampUrl,
                timestampUrlOffset,
            ) = unpack('<LLLLLLLLL', data[0:9*4])
            signatureOffset -= offset
            self.pbSignatureBuffer = data[
                signatureOffset:signatureOffset + cbSignature]
            certStoreOffset -= offset
            self.pbSigningCertStoreBuffer = data[
                certStoreOffset:certStoreOffset + cbSigningCertStore]
            projectNameOffset -= offset
            self.rgchProjectNameBuffer = data[
                projectNameOffset:projectNameOffset + cbProjectName]
            timestampUrlOffset -= offset
            self.rgchTimestampBuffer = data[
                timestampUrlOffset:timestampUrlOffset + cbTimestampUrl]
            logger.debug("DigSigInfoSerialized: Signature ({} bytes) from {}: {}...".format(cbSignature, signatureOffset, hexlify(data[signatureOffset:50])))
            logger.debug("DigSigInfoSerialized: CertStore ({} bytes) from {}: {}...".format(cbSigningCertStore, certStoreOffset, hexlify(data[cbSigningCertStore:50])))
            logger.debug("DigSigInfoSerialized: ProjectName ({} bytes) from {}: {}...".format(cbProjectName, projectNameOffset, hexlify(data[projectNameOffset:50])))

        else:
            self._initialized = False
            self.pbSignatureBuffer = None
            self.pbSigningCertStoreBuffer = None
            self.rgchProjectNameBuffer = None
            self.rgchTimestampBuffer = None

    def get_block(self, offset=None):
        if not self._initialized:
            raise ValueError("Instance of DigSigInfoSerialized is not initialized")

        if offset is None:
            offset = self.offset

        cbSignature = len(self.pbSignatureBuffer)
        signatureOffset = offset
        offset += cbSignature

        cbSigningCertStore = len(self.pbSigningCertStoreBuffer)
        certStoreOffset = offset
        offset += cbSigningCertStore

        cbProjectName = len(self.rgchProjectNameBuffer)
        projectNameOffset = offset
        offset += cbProjectName

        fTimestamp = 0

        cbTimestampUrl = len(self.rgchTimestampBuffer)
        timestampUrlOffset = offset
        offset += cbTimestampUrl

        first_part = pack('<LLLLLLLLL',
                          cbSignature,
                          signatureOffset,
                          cbSigningCertStore,
                          certStoreOffset,
                          cbProjectName,
                          projectNameOffset,
                          fTimestamp,
                          cbTimestampUrl,
                          timestampUrlOffset,)

        return first_part + self.pbSignatureBuffer + self.pbSigningCertStoreBuffer + self.rgchProjectNameBuffer + self.rgchTimestampBuffer

# Sometimes the DigSigInfoSerialized struct is contained in one of these:
# DigSigBlob or WordSigBlob

# [MS-OSHARED] 2.3.2.2 DigSigBlob

class DigSigBlob:

    def __init__(self, data=None):

        if data:
            logger.debug("DigSigBlob ({} bytes): ".format(len(data)) + str(hexlify(data)))
            (
                cb,
                serializedPointer,
            ) = unpack('<LL', data[0:8])
            if serializedPointer != 8:
                raise ValueError("Invalid DigSigBlob, serializedPointer={}".format(serializedPointer))
            logger.debug("DigSigBlob: cb={} serializedPointer={}".format(cb, serializedPointer)) 
            self.signatureInfo = DigSigInfoSerialized(
                data[serializedPointer:],
                offset=serializedPointer)
        else:
            self.signatureInfo = None

    def get_block(self):
        if not self.signatureInfo:
            raise ValueError("Instance of DigSigBlob is not initialized")

        signatureInfo = self.signatureInfo.get_block(offset=12)
        cbSigInfo = len(signatureInfo)
        serializedPointer = 8
        cch = (cbSigInfo + (cbSigInfo % 2) + 8) / 2
        first_part('<LL', cb, cbSigInfo, serializedPointer)
        first
        if cbSiginfo % 2 == 0:
            padding = b''
        else:
            padding = b'0x0'
      
        return first_part + signatureInfo + padding

# [MS-OSHARED] 2.3.2.3 WordSigBlob

# cch (2 bytes): An unsigned integer that specifies half the count of
# bytes of the remainder of the structure. MUST be the value given by
# the following formula.
#
#    cch = (cbSigInfo + (cbSigInfo mod 2) + 8) / 2

# cbSigInfo (4 bytes): An unsigned integer that specifies the size of
# the signatureInfo field in bytes.

# serializedPointer (4 bytes): An unsigned integer that specifies the
# offset of the signatureInfo field within this structure relative to
# the cbSigInfo field. MUST be 0x00000008.

# signatureInfo (variable): A DigSigInfoSerialized structure (section
# 2.3.2.1) containing the data for the signature.

# padding (variable): An array of bytes. The size of this array is the
# number of bytes necessary to pad the entire structure’s size to a
# multiple of 2 bytes. The contents of this field are undefined and
# MUST be ignored.

class WordSigBlob:

    def __init__(self, data=None):

        if data:
            logger.debug("WordSigBlob ({} bytes): ".format(len(data)) + str(hexlify(data)))
            (
                cch,
                cbSigInfo,
                serializedPointer,
            ) = unpack('<HLL', data[0:10])
            logger.debug("WordSigBlob: cch={} cbSigInfo={} serializedPointer={}".format(cch, cbSigInfo, serializedPointer)) 
            self.signatureInfo = DigSigInfoSerialized(
                data[10:10+cbSigInfo],
                offset=12)

        else:
            self.signatureInfo = None

    def get_block(self):
        if not self.signatureInfo:
            raise ValueError("Instance of DigSigBlob is not initialized")

        signatureInfo = self.signatureInfo.get_block(offset=12)
        cbSigInfo = len(signatureInfo)
        serializedPointer = 8
        cch = (cbSigInfo + (cbSigInfo % 2) + 8) / 2
        first_part('<HLL', cch, cbSigInfo, serializedPointer)
        first
        if cbSiginfo % 2 == 0:
            padding = b''
        else:
            padding = b'0x0'
      
        return first_part + signatureInfo + padding
    
from enum import Enum

# class syntax

class SignatureKind(Enum):
    LEGACY = 1
    AGILE = 2
    V3 = 3

sig_offset = 8 # 8 for DigSigBlob, 10 for WordSigBlob

# TODO: Maybe split signature kinds to separate files
class VbaProjectSignature:

    def __init__(self, ooxml, kind, part_name=None, part=None):
        self.ooxml = ooxml
        self.kind = kind
        self.part_name = part_name
        self.part = part
        self.signature = None

    @classmethod
    def get(cls, ooxml, kind):
        logger.error("Deprecated method signature.vbaProjectSignature.get()")
        return ooxml.get_signature(kind)

    @classmethod
    def get_class(cls, kind):
        if kind == SignatureKind.LEGACY:
            return VbaProjectSignatureLegacy
        elif kind == SignatureKind.AGILE:
            return VbaProjectSignatureAgile
        elif kind == SignatureKind.V3:
            return VbaProjectSignatureV3
        else:
            raise ValueError("Unknown signature kind {}".format(kind))
    
    @classmethod
    def parse(cls, ooxml, kind, part_name, part):
        # We ignore class
        new_class = cls.get_class(kind)
        self = new_class(ooxml, kind, part_name, part)

        # Offsets in a DigSigInfoSerialized are relative to an enclosing
        # structure. But the enclosing structure is not present in our case.
        # So we need to tell the extractor about the offset value.
        self.sig_info = DigSigInfoSerialized(part, sig_offset)
        try:
            self.signature = pkcs7.ContentInfo.parse(data=self.sig_info.pbSignatureBuffer)
        except pkcs7.ASN1Error as e:
            print('\nError de ASN1:')
            print("Se esperaba %s" % str(e.args[0]['expected']))
            print("Se encontró %s" % str(e.args[0]['found']))
            raise

        return self

    @property
    def signatureHash(self):
        raise NotImplementedError

    @property
    def digestAlgorithmOID(self):

        signedData = self.signature.content
        dataContent = signedData.contentInfo.content
        digestInfo = dataContent.messageDigest
        return digestInfo.digestAlgorithm

keep_signature_copies = True
keep_normalized_copies = True

class VbaProjectSignatureLegacy(VbaProjectSignature):

    def analyze(self):
        if keep_signature_copies:
            open('sig_legacy.p7b', 'wb').write(self.sig_info.pbSignatureBuffer)

        logger.info(self.signature)
        signedData = self.signature.content
        logger.info(signedData)
        logger.info(signedData.digestAlgorithms)
        logger.info(signedData.contentInfo)
        for si in signedData.signerInfos:
            logger.info(si)

        dataContent = signedData.contentInfo.content
        data = dataContent.data
        logger.info(data)
        digestInfo = dataContent.messageDigest
        logger.debug(digestInfo.digestAlgorithm)
        logger.debug(digestInfo.digest)

    @classmethod
    def contentHash(cls, vbaProject, digestAlgorithmOID):
        # TBC: Remove from vbaProject
        ContentBuffer = bytearray()

        ContentNormalizedData = vbaProject.ContentNormalizedData()

        logger.info("ContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)

        if keep_normalized_copies:
            open("NormalizedData.bin", "wb").write(ContentBuffer)
        digest_algorithm = oid2hashlib(digestAlgorithmOID)
        hash = digest_algorithm(ContentBuffer)
        logger.debug("ContentHash: %s" % hash.hexdigest())
        return hash
    
    @property
    def signatureHash(self):

        signedData = self.signature.content
        spcidc = signedData.contentInfo.content
        return spcidc.messageDigest.digest

class VbaProjectSignatureAgile(VbaProjectSignature):

    def analyze(self):
        if keep_signature_copies:
            open('sig_agile.p7b', 'wb').write(self.sig_info.pbSignatureBuffer)

        logger.info(self.signature)
        signedData = self.signature.content
        logger.info(signedData)
        logger.info(signedData.digestAlgorithms)
        logger.info(signedData.contentInfo)
        for si in signedData.signerInfos:
            logger.info(si)

        dataContent = signedData.contentInfo.content
        data = dataContent.data
        logger.info(data)
        digestInfo = dataContent.messageDigest
        logger.debug(digestInfo.digestAlgorithm)
        logger.debug(digestInfo.digest)

    @classmethod
    def contentHash(cls, vbaProject, digestAlgorithmOID):
        # TBC: Remove from vbaProject
        ContentBuffer = bytearray()

        # MS-OVBA 2.4.2.1
        ContentNormalizedData = vbaProject.ContentNormalizedData()

        logger.info("AgileContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)

        # MS-OVBA 2.4.2.2
        FormsNormalizedData = vbaProject.FormsNormalizedData()
        logger.info("FormsNormalizedData: %s" % hexlify(FormsNormalizedData))
        ContentBuffer.extend(FormsNormalizedData)

        if keep_normalized_copies:
            open("AgileNormalizedData.bin", "wb").write(ContentBuffer)

        digest_algorithm = oid2hashlib(digestAlgorithmOID)
        hash = digest_algorithm(ContentBuffer)
        return hash
    
    @property
    def signatureHash(self):

        signedData = self.signature.content
        spcidc = signedData.contentInfo.content
        # return spcidc.messageDigest.digest
        return spcidc.messageDigest.digest_parsed.sourceHash

class VbaProjectSignatureV3(VbaProjectSignature):

    def analyze(self):
        if keep_signature_copies:
            open('sig_v3.p7b', 'wb').write(self.sig_info.pbSignatureBuffer)

        logger.info(self.signature)
        signedData = self.signature.content
        logger.info(signedData)
        logger.info(signedData.digestAlgorithms)
        logger.info(signedData.contentInfo)
        for si in signedData.signerInfos:
            logger.info(si)

        dataContent = signedData.contentInfo.content
        data = dataContent.data
        logger.info(data)
        digestInfo = dataContent.messageDigest
        logger.debug(digestInfo.digestAlgorithm)
        logger.debug(digestInfo.digest)

    @classmethod
    def contentHash(cls, vbaProject, digestAlgorithmOID):
        # TBC: Remove from vbaProject
        ContentBuffer = bytearray()
        # 2.4.2.5 V3 Content Normalized Data

        ContentNormalizedData = vbaProject.v3_content_normalized_data()
        logger.info("V3ContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)

        # 2.4.2.6 Project Normalized Data
        ProjectNormalizedData = vbaProject.ProjectNormalizedData()
        logger.debug("ProjectNormalizedData: %s" % hexlify(ProjectNormalizedData))
        ContentBuffer.extend(ProjectNormalizedData)

        open("V3NormalizedData.bin", "wb").write(ContentBuffer)

        if keep_normalized_copies:
            open("V3NormalizedData.bin", "wb").write(ContentBuffer)

        digest_algorithm = oid2hashlib(digestAlgorithmOID)
        hash = digest_algorithm(ContentBuffer)
        return hash
    
    @property
    def signatureHash(self):

        signedData = self.signature.content
        spcidc = signedData.contentInfo.content
        # return spcidc.messageDigest.digest
        return spcidc.messageDigest.digest_parsed.sourceHash
