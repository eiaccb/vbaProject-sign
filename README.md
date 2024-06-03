# vbaProject-sign
Tools to handle signatures for OpenXML VBA macros

The goal is to create signatures for macros in OpenXML MS Office documents.

Macros are stored in a structure by default called vbaProject.bin that has to be parsed to extract information.

Current status is:

    - Correct computation of MS-OVBA 2.4.2.3 Content Hash
    - Correct computation of MS-OVBA 2.4.2.4 Agile Content Hash
    - Correct computation of MS-OVBA 2.4.2.7 V3 Content Hash

Still missing:

    - Actual signatures. Recent versions of pyca cryptography have
      added limited support for this in ...pkcs7.PKCS7SignatureBuilder,
      but it cannot produce a ContentInfo structure with 
      1.3.6.1.4.1.311.2.1.29 (Microsoft SpcIndirectDataContent) or
      1.3.6.1.4.1.311.2.1.31 (Microsoft SpcIndirectDataContentV2) or
      the SigDataV1Serialized structure.

