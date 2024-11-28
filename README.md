# vbaProject-sign
Tools to handle signatures for OfficeOpenXML VBA macros

The goal is to create signatures for macros in MS OfficeOpenXML documents.

Macros are stored in a structure by default called vbaProject.bin that has to be parsed to extract information.

Current status is:

    - Correct computation of MS-OVBA 2.4.2.3 Content Hash
    - Correct computation of MS-OVBA 2.4.2.4 Agile Content Hash
    - Correct computation of MS-OVBA 2.4.2.7 V3 Content Hash
      - Some cases still fail
    - Correct computation of DigSigInfoSerialized in the three
      formats for all cases tried (if the hash is right)
    - Correct signatures for the three formats

Still missing:

    - Adding signatures to files that did not contain them

