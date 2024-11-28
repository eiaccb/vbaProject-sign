
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
from binascii import hexlify, unhexlify
import hashlib
from enum import Enum
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import asn1

import vbaProject
import pkcs7

debug_info = {
    'debugging': True,
    'keep_files': True,
    'properties': [
        (0x0000000f,
         unhexlify('08760cfe7dae8dec5fdeea8af4e05ee04e5f7e9226525aa92f5e755e3597ca08'))
    ],
    'SigDataV1Serialized-compiledHash': unhexlify('2A32CDC306490311AAC4EF27E22A9B62D21F1788238D17DF96DE4082D029E716'),
   
}

MD5_OID = x509.ObjectIdentifier('1.2.840.113549.2.5')
SHA256_OID = x509.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
SHA512_OID = x509.ObjectIdentifier('2.16.840.1.101.3.4.2.3')

def oid2hashlib(digestAlgorithm):
    if isinstance(digestAlgorithm, str):
        oid = digestAlgorithm
    elif isinstance(digestAlgorithm, x509.ObjectIdentifier):
        oid = digestAlgorithm.dotted_string
    else:
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
            self.rgchProjectNameBuffer = unhexlify('0000')
            self.rgchTimestampBuffer = unhexlify('0000')

    def as_bytes(self, offset=None):
        if self.pbSignatureBuffer and self.pbSigningCertStoreBuffer:
            self._initialized = True
        if not self._initialized:
            raise ValueError("Instance of DigSigInfoSerialized is not initialized")

        if offset is None:
            offset = self.offset

        # Nine longs in the first part
        offset += 9 * 4
    
        cbSignature = len(self.pbSignatureBuffer)
        signatureOffset = offset
        offset += cbSignature

        cbSigningCertStore = len(self.pbSigningCertStoreBuffer)
        certStoreOffset = offset
        offset += cbSigningCertStore

        if self.rgchProjectNameBuffer:
            projectName = self.rgchProjectNameBuffer
        else:
            projectName = unhexlify('0000')
        cbProjectName = len(projectName)
        projectNameOffset = offset
        offset += cbProjectName

        fTimestamp = 0

        if self.rgchTimestampBuffer:
            timestamp = self.rgchTimestampBuffer
        else:
            timestamp = unhexlify('0000')
        cbTimestampUrl = len(timestamp)
        timestampUrlOffset = offset
        offset += cbTimestampUrl

        first_part = pack('<LLLLLLLLL',
                          cbSignature,
                          signatureOffset,
                          cbSigningCertStore,
                          certStoreOffset,
                          cbProjectName - 2,
                          projectNameOffset,
                          fTimestamp,
                          cbTimestampUrl - 2,
                          timestampUrlOffset,)

        return first_part + self.pbSignatureBuffer + self.pbSigningCertStoreBuffer + projectName + timestamp

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

class SpcAttributeTypeAndOptionalValue:

    def __init__(self, type, value=None):
        self.type = type
        self.value = value

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.type.dotted_string, asn1.Numbers.ObjectIdentifier)

        if self.value:
            # [0] EXPLICIT ANY OPTIONAL
            encoder.write(self.value, asn1.Numbers.OctetString)

        encoder.leave()

# MS-OSHARED 2.2.2.4.3.2
class SpcIndirectDataContentV2:

    def __init__(self, data=None, messageDigest=None):
        self.data = data
        self.messageDigest = messageDigest

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        self.data.asn1_serialize(encoder)
        self.messageDigest.asn1_serialize(encoder)
        encoder.leave()

class SigFormatDescriptorV1(pkcs7.ASN1Data):
    def __init__(self, size=None, version=None, format=None):
        self.size = size
        self.version = version
        self.format = format

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.size)
        encoder.write(self.version)
        encoder.write(self.format)
        encoder.leave()

    def as_bytes(self):
        result = pack('<LLL', self.size, self.version, self.format)
        return result

class SigDataV1Serialized :
    def __init__(self, algorithmId, compiledHash, sourceHash):
        self.algorithmId = algorithmId
        self.compiledHash = compiledHash
        self.sourceHash = sourceHash

    def as_bytes(self):
        # Don't miss this, a null-terminated dotted string
        algorithmId = self.algorithmId.algorithm.dotted_string.encode('ascii') + b'\0'
        algorithmIdSize = len(algorithmId)
        if debug_info['debugging'] and 'SigDataV1Serialized-compiledHash' in debug_info:
            compiledHash = debug_info['SigDataV1Serialized-compiledHash']
        else:
            compiledHash = b''
        algorithmIdSize = len(algorithmId)
        compiledHashSize = len(compiledHash)
        sourceHashSize = len(self.sourceHash)

        first_part = pack(
            '<LLLLLL',
            algorithmIdSize,
            compiledHashSize,
            sourceHashSize,
            24,
            24 + algorithmIdSize,
            24 + algorithmIdSize + compiledHashSize
        )

        result = first_part + algorithmId + compiledHash + self.sourceHash
        return result

# MS-OSHARED 2.3.2.4.4.1
class SpcStatementType:

    def __init__(self, value=None):
        self._oid = x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.11')
        self._statement_types = []
        if value:
            if isinstance(value, x509.ObjectIdentifier):
                self._statement_types.append(value)
            else:
                self._statement_types.append(x509.ObjectIdentifier(value))

    # TBC: Implement parse from py-pkcs7

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        for s_type in self._statement_types:
            encoder.write(s_type.dotted_string, asn1.Numbers.ObjectIdentifier)
        encoder.leave()
    
# MS-OSHARED 2.3.2.4.4.2
class SpcSpOpusInfo:

    def __init__(self, program_name=None):
        self._oid = x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.11')
        self._program_name = program_name

    # TBC: Implement parse from py-pkcs7

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.enter(0, asn1.Classes.Context)
        encoder.write(b'', 0, asn1.Classes.Context)
        encoder.leave()
        encoder.leave()

# MS-OSHARED 2.3.2.5.1
class SerializedCertificateEntry():

    def __init__(self, certificate=None):
        self.certificate = certificate
        
    @classmethod
    def parse(cls, data, offset):
        self = cls()
        ( id, encodingType, length ) = unpack('<LLL', data[offset:offset+12])
        if id != 0x00000020:
            raise ValueError("Invalid Id value, expecting 0x00000020, found 0x{:8X}".format(id))
        certbytes = data[offset+12:offset+12+length]
        self.id = id
        self.encodingType = encodingType
        self.length = length
        self.certbytes = certbytes
        self.certificate = x509.load_der_x509_certificate(self.certbytes)

        logger.debug("Loaded certificate for {}".format(self.certificate.subject))
        
        return self, offset+12+length

    def as_bytes(self):
        cert_bytes = self.certificate.public_bytes(serialization.Encoding.DER)
        first_part = pack('<LLL', 0x00000020, 0x00000001, len(cert_bytes))
        return first_part + cert_bytes

# MS-OSHARED 2.3.2.5.3
class EndElementMarkerEntry():

    @classmethod
    def parse(cls, data):
        id, marker = unpack('<LQ', data)

        self = cls()
        self.id = id
        self.marker = marker

        return self

    def as_bytes(self):
        result = pack('<LQ', 0x00000000, 0x0000000000000000)
        return result

# MS-OSHARED 2.3.2.5.3
# Note <13>:  [Many Office versions] write properties in the digital certificate store as a byproduct of the way the digital certificate store is constructed, but none of the properties specify any behavior and are ignored when encountered.
class SerializedPropertyEntry():

    def __init__(self, id=None, encodingType=0x00000001, value=None):
        self.id = id
        self.encodingType = encodingType
        self.value = value

    @classmethod
    def parse(cls, data, offset):

        ( id, encodingType, length ) = unpack('<LLL', data[offset:offset+12])
        value = data[offset+12:offset+12+length]
        self = cls(id=id, encodingType=encodingType, value=value)

        logger.debug("Property: {}".format(hexlify(self.value)))

        return self, offset + 12 + length

    def as_bytes(self):
        first_part = pack('<LLL', self.id, self.encodingType, len(self.value))
        return first_part + self.value

# MS-OSHARED 2.3.2.5.4
class CertStoreCertificateGroup():

    def __init__(self, elementList=[], certificate=None):
        self.elementList = elementList
        if debug_info['debugging']:
            self.elementList = []
            for e in debug_info['properties']:
                id, value = e
                e = SerializedPropertyEntry(id=id, value=value)
                self.elementList.append(e)
        
        if certificate:
            self.serialized_certificate = SerializedCertificateEntry(certificate)
        else:
            self.serialized_certificate = None

    @classmethod
    def parse(cls, data):
        logger.debug("Inside CertStoreCertificateGroup.parse")
        
        elementList = []
        offset = 0
        while True:
            next_id = unpack('<L', data[offset:offset+4])[0]
            if next_id == 0x00000020:
                break
            element, offset = SerializedPropertyEntry.parse(data, offset)
            elementList.append(element)
        serialized_certificate = SerializedCertificateEntry.parse(data, offset)
        self = cls()
        self.elementList = elementList
        self.serialized_certificate = serialized_certificate

        return self

    def as_bytes(self):
        parts = []
        for element in self.elementList:
            parts.append(element.as_bytes())
        parts.append(self.serialized_certificate.as_bytes())
        return b''.join(parts)

# MS-OSHARED 2.3.2.5.5
class VBASigSerializedCertStore():

    def __init__(self, version=0, fileType=0x54524543, certGroup=None, certificate=None):
        self.version = version
        self.fileType = fileType
        self.certGroup = certGroup
        self.certificate = certificate

        if not certGroup and self.certificate:
            self.certGroup = CertStoreCertificateGroup(certificate=self.certificate)

        self.endMarkerElement = None

    @classmethod
    def parse(cls, data):
        logger.debug("Inside VBASigSerializedCertStore.parse")
        (
            version,
            fileType,
        ) = unpack('<LL', data[0:8])

        if version != 0:
            raise ValueError("Invalid version {} for VBASigSerializedCertStore".format(version))

        # IDEA!!!! Resign the sample macros with our certificate so that
        # data matches better
        if fileType != 0x54524543:
            # TREC (CERT backwards, we could have read it as string
            # but we decoded it as a little-endian logn)
            raise ValueError("Invalid fileType {} for VBASigSerializedCertStore".format(fileType))

        certGroup = CertStoreCertificateGroup.parse(data[8:-12])

        endMarkerElement = EndElementMarkerEntry.parse(data[-12:])

        self = cls()
        self.version = version
        self.fileType = fileType
        self.certGroup = certGroup
        self.endMarkerElement = endMarkerElement

        logger.debug("End: VBASigSerializedCertStore.parse version:0x{:08X} fileType:0x{:8X}".format(self.version, self.fileType))

        return self

    def as_bytes(self):
        first_part = pack('<LL', self.version, self.fileType)
        certGroup = self.certGroup.as_bytes()
        if not self.endMarkerElement:
            self.endMarkerElement = EndElementMarkerEntry()
        endMarkerElement = self.endMarkerElement.as_bytes()

        return first_part + certGroup + endMarkerElement

# class syntax

class SignatureKind(Enum):
    LEGACY = 1
    AGILE = 2
    V3 = 3

    def __str__(self):
        if self == self.LEGACY:
            return('Legacy')
        elif self == self.AGILE:
            return('Agile')
        elif self == self.V3:
            return('V3')
        else:
            raise ValueError("Bad Kind value {}".format(self))

    @classmethod
    def choices(cls):
        return [cls.LEGACY, cls.AGILE, cls.V3]
    
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
        logger.debug("Getting class {}".format(kind))
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
        if debug_info['debugging'] and debug_info['keep_files']:
            open(str(kind) + '-input-DigSigInfoSerialized.bin', 'wb').write(part)
        # We ignore cls
        new_class = cls.get_class(kind)
        self = new_class(ooxml, kind, part_name, part)

        logger.debug("Inside {} VbaProjectSignature.parse".format(kind))
        # Offsets in a DigSigInfoSerialized are relative to an enclosing
        # structure. But the enclosing structure is not present in our case.
        # So we need to tell the extractor about the offset value.
        self.sig_info = DigSigInfoSerialized(part, sig_offset)
        
        try:
            if debug_info['debugging'] and debug_info['keep_files']:
                open(str(kind) + '-input-pbSignatureBuffer.bin', 'wb').write(self.sig_info.pbSignatureBuffer)
            self.signature = pkcs7.ContentInfo.parse(data=self.sig_info.pbSignatureBuffer)
        except pkcs7.ASN1Error as e:
            logger.error('\nError de ASN1:')
            logger.error("Se esperaba %s" % str(e.args[0]['expected']))
            logger.error("Se encontró %s" % str(e.args[0]['found']))
            raise

        try:
            if debug_info['debugging'] and debug_info['keep_files']:
                open(str(kind) + '-input-pbSigningCertStoreBuffer.bin', 'wb').write(self.sig_info.pbSigningCertStoreBuffer)
            self.certStore = VBASigSerializedCertStore.parse(self.sig_info.pbSigningCertStoreBuffer)
        except ValueError:
            logger.error("\nError analyzing pbSigningCertStoreBuffer")
            raise
        logger.debug("End: {} VbaProjectSignature.parse".format(kind))
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
        if debug_info['debugging'] and debug_info['keep_files']:
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
    def requiredDigestAlgorithm(cls):
        return MD5_OID

    @classmethod
    def contentHash(cls, vbaProject, digestAlgorithmOID):
        # TBC: Remove from vbaProject
        ContentBuffer = bytearray()

        ContentNormalizedData = vbaProject.ContentNormalizedData()

        logger.info("ContentNormalizedData: %s" % hexlify(ContentNormalizedData))
        ContentBuffer.extend(ContentNormalizedData)

        if debug_info['debugging'] and debug_info['keep_files']:
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

    @classmethod
    def get_content(cls, messageDigest):

        encoder = asn1.Encoder()

        encoder.start()
        encoder.enter(asn1.Numbers.Sequence) # SpcIndirectDataContent

        SpcAttributeTypeAndOptionalValue(
            x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.29'),
            unhexlify('D35C18ABD06431C1FDFFEB811981F45E'),
        ).asn1_serialize(encoder)

        encoder.enter(asn1.Numbers.Sequence) # DigestInfo

        encoder.enter(asn1.Numbers.Sequence) # AlgorithmIdentifier
        encoder.write(messageDigest.digestAlgorithm.algorithm.dotted_string,
                      asn1.Numbers.ObjectIdentifier)
        encoder.write(None)
        encoder.leave()
        encoder.write(messageDigest.digest, asn1.Numbers.OctetString)

        encoder.leave()                      # DigestInfo

        encoder.leave()                      # SpcIndirectDataContent 

        content = encoder.output()

        return content

class VbaProjectSignatureAgile(VbaProjectSignature):

    def analyze(self):
        if debug_info['debugging'] and debug_info['keep_files']:
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
    def requiredDigestAlgorithm(cls):
        return SHA256_OID

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

        if debug_info['debugging'] and debug_info['keep_files']:
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

    @classmethod
    def get_content(cls, inputMessageDigest):

        encoder = asn1.Encoder()
        encoder.start()

        # Documentation states this must ba a DER encoding,
        # Our samples just encode the three long integers one after
        # the other in little endian format
        struct_size = 12 # What is this?
        format_descriptor = SigFormatDescriptorV1(
            struct_size, 1, 1
        ).as_bytes()

        digest = SigDataV1Serialized(
            inputMessageDigest.digestAlgorithm,
            b'',
            inputMessageDigest.digest).as_bytes()

        messageDigest = pkcs7.DigestInfo(
            inputMessageDigest.digestAlgorithm,
            digest)

        spcAttributeTypeAndOptionalValue = SpcAttributeTypeAndOptionalValue(
            type=x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.31'),
            value=format_descriptor,
        )
        
        SpcIndirectDataContentV2(
            data=spcAttributeTypeAndOptionalValue,
            messageDigest=messageDigest,
        ).asn1_serialize(encoder)

        content = encoder.output()

        return content

class VbaProjectSignatureV3(VbaProjectSignature):

    def analyze(self):
        if debug_info['debugging'] and debug_info['keep_files']:
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
    def requiredDigestAlgorithm(cls):
        # TBC: Temporary change for testing
        # return SHA512_OID
        return SHA256_OID

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

        if debug_info['debugging'] and debug_info['keep_files']:
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

    @classmethod
    def get_content(cls, inputMessageDigest):

        encoder = asn1.Encoder()
        encoder.start()

        # Documentation states this must ba a DER encoding,
        # Our samples just encode the three long integers one after
        # the other in little endian format
        struct_size = 12 # What is this?
        format_descriptor = SigFormatDescriptorV1(
            struct_size, 1, 1
        ).as_bytes()

        digest = SigDataV1Serialized(
            inputMessageDigest.digestAlgorithm,
            b'',
            inputMessageDigest.digest).as_bytes()

        messageDigest = pkcs7.DigestInfo(
            inputMessageDigest.digestAlgorithm,
            digest)

        spcAttributeTypeAndOptionalValue = SpcAttributeTypeAndOptionalValue(
            type=x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.31'),
            value=format_descriptor,
        )
        
        SpcIndirectDataContentV2(
            data=spcAttributeTypeAndOptionalValue,
            messageDigest=messageDigest,
        ).asn1_serialize(encoder)

        content = encoder.output()

        return content

class VbaProjectSignatureBuilder:

    def __init__(self, kind):
        self.kind = kind

    def set_vbaProject(self, project):
        self.vbaProject = project
        return self

    def set_certificates(self, certificates):
        self.signer_certificate = certificates[0]
        self.other_certificates = certificates[1:]
        return self

    def sign(self, signer_engine):
        sig_cls = VbaProjectSignature.get_class(self.kind)

        digestAlgorithm = sig_cls.requiredDigestAlgorithm()
        try:
            digest = sig_cls.contentHash(self.vbaProject, digestAlgorithm).digest()
        except vbaProject.KnownBug as e:
            logger.error(e)
            return None
        messageDigest = pkcs7.DigestInfo(
            pkcs7.DigestAlgorithmIdentifier(digestAlgorithm),
            digest
        )

        contentType = x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.4')

        logger.debug("TEST: messageDigest:        {}".format(hexlify(messageDigest.digest)))

        content = sig_cls.get_content(messageDigest)
        # Please see RFC2315, 9.3 Message-digesting process
        # Only the contents octets of the DER encoding of that field are
        # digested, not the identifier octets or the length octets.
        hash_function = oid2hashlib(messageDigest.digestAlgorithm)
        decoder = asn1.Decoder()
        decoder.start(content)
        content_tag, content_value = decoder.read()
        logger.debug("TEST: content to hash:      {}".format(hexlify(content_value)))
        hash_value = hash_function(content_value).digest()
        logger.debug("TEST: content hash to sign: {}".format(hexlify(hash_value)))
        new_messageDigest = pkcs7.DigestInfo(
            messageDigest.digestAlgorithm,
            hash_value
        )
        
        pkcs7_builder = pkcs7.SignedDataBuilder()
        signer_engine.set_digest_algorithm(sig_cls.requiredDigestAlgorithm())

        # Attributes is composed of sequences. Each sequence is composed
        # of an OID and a set of values
        # The order we have found is:
        # 1.3.6.1.4.1.311.2.1.12 SPC_SP_OPUS_INFO_OBJID (microsoft)
        # 1.2.840.113549.1.9.3 contentType with value 1.3.6.1.4.1.311.2.1.4
        # 1.3.6.1.4.1.311.2.1.11 SPC_STATEMENT_TYPE_OBJID with value Microsoft Individual Code Signing (parece que 1.3.6.1.4.1.311.2.1.21)
        # 1.2.840.113549.1.9.4 messageDigest with a value (should match the one computed as ContentHash)
        # pkcs7_builder.add_authenticated_attribute(
        #    '1.3.6.1.4.1.311.2.1.12', 
        # )
        pkcs7_builder.add_authenticated_attribute(
            oid=x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.12'),
            values=[SpcSpOpusInfo()])
        pkcs7_builder.add_authenticated_attribute(
            oid=x509.ObjectIdentifier('1.2.840.113549.1.9.3'),
            values=[pkcs7.PKCS9_ContentType('1.3.6.1.4.1.311.2.1.4')])
        pkcs7_builder.add_authenticated_attribute(
            oid=x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.11'),
            values=[SpcStatementType('1.3.6.1.4.1.311.2.1.21')])
        pkcs7_builder.add_authenticated_attribute(
            oid=x509.ObjectIdentifier('1.2.840.113549.1.9.4'),
            values=[pkcs7.PKCS9_MessageDigest(new_messageDigest)])
        pkcs7_builder.add_content(contentType, content)
        pkcs7_builder.add_signer(self.signer_certificate)
        pkcs7_builder.add_digest_algorithm(sig_cls.requiredDigestAlgorithm())
        for certificate in self.other_certificates:
            pkcs7_builder.add_extra_certificate(certificate)
        pkcs7_builder.set_signer_engine(signer_engine)
        
        dsis = DigSigInfoSerialized()
        
        sig_bytes = pkcs7_builder.output(format='DER')
        dsis.pbSignatureBuffer = sig_bytes

        certStore_bytes = VBASigSerializedCertStore(certificate=self.signer_certificate).as_bytes()
        dsis.pbSigningCertStoreBuffer = certStore_bytes

        dsis_bytes = dsis.as_bytes(offset=8)
        if debug_info['debugging'] and debug_info['keep_files']:
            open("{}-SignatureResult.p7b".format(self.kind),'wb').write(sig_bytes)
            open("{}-VBASigSerializedCertStore.bin".format(self.kind),'wb').write(certStore_bytes)
            open("{}-DigSigInfoSerialized.bin".format(self.kind),'wb').write(dsis_bytes)

        return dsis_bytes
