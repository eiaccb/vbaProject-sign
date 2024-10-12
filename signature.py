

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

from struct import pack, unpack

# [MS-OSHARED] 2.3.2.1 DigSigInfoSerialized

# Notice that notionally, a DigSigInfoSerialized is considered part
# of an enclosing structure and the offsets in DigSigInfoSerialized
# must be understood relative to that strucuture. So that we can
# reuse this implementation, we ask for the offset of DigSigInfoSerialized
# in the enclosing structure so that we can adjust the values.

class DigSigInfoSerialized:

    def __init__(self, data=None, offset=0):

        if data:
            self._initialized = False
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
            ) unpack('<LLLLLLLLL', data[0:9*4])
            self.pbSignatureBuffer = data[
                signatureOffset - offset,
                signatureOffset - offset + cbSignature]
            self.pbSigningCertStoreBuffer = data[
                certStoreOffset - offset,
                certStoreOffset - offset + cbSigningCertStore]
            self.rgchProjectNameBuffer = data[
                projectNameOffset - offset,
                projectNameOffset - offset + cbProjectName]
            self.rgchTimestampBuffer = data[
                timestampUrlOffset - offset,
                timestampUrlOffset - offset + cbTimestampUrl]

        else:
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

class DigSigBlob:

    def __init__(self, data=None):

        if data:
            (
                cch,
                cbSigInfo,
                serializedPointer,
            ) unpack('<HLL', data[0:10])
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
        cch = (cbSigInfo + (cbSigInfo mod 2) + 8) / 2
        first_part('<HLL', cch, cbSigInfo, serializedPointer)
        first
        if cbSiginfo % 2 == 0:
            padding = b''
        else:
            padding = b'0x0'
      
        return first_part + signatureInfo + padding
    
# [MS-OSHARED] 2.3.2.3 WordSigBlob
