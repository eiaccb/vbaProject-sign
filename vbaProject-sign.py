#!/usr/bin/env python3

import sys
import os
import logging

logging.basicConfig(level=logging.WARNING)

logger = logging.getLogger(__name__)
# logger.setLevel(logging.WARNING)
# logger.addHandler(logging.StreamHandler())

import argparse

import getpass
from binascii import hexlify
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# sys.path.append(os.path.join(os.path.dirname(sys.path[0]), 'lib'))
# sys.path.insert(0, os.path.join(os.path.dirname(sys.path[0]), 'lib'))
mydir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(mydir, 'git-work', 'vbaProject-sign'))
sys.path.insert(0, os.path.join(mydir, 'git-work', 'officeparser'))
sys.path.insert(0, os.path.join(mydir, 'git-work', 'py-pkcs7'))

# print(sys.path)

from ooxml import OfficeOpenXML
import vbaProject
from signature import SignatureKind, VbaProjectSignature
from signer_engine import PrivateKeySignerEngine
from vault_signer_engine import VaultSignerEngine


# Operations:

# analyze: Checks an OfficeXML file. If it has macros, it analyzes
# 	the file and reports on the different hashes.
#	If it contains signatures, checks the validity of the signatures
#	It also compares the hashes in the signatures against those
#	computed.
# sign: Creates missing signatures or new signatures to replace those
#	invalid or all of them
# analyze-intermediate: Parses an intermediate result. Only V3.

def analyze(filename):

    oxml = OfficeOpenXML(filename)
    logger.debug("Loaded OfficeOpenXML from %s" % filename)

    if not oxml.has_macros:
        print("El archivo %s no tiene macros" % filename)
        return

    if oxml.has_signed_macros_legacy:
        logger.debug("================ Legacy signature =================")
        print("=================== Legacy signature =====================")
        signature = oxml.get_signature(SignatureKind.LEGACY)
        signature.analyze()
        logger.debug("Loaded legacy signature")
        signedData = signature.signature.content
        for algorithm in signedData.digestAlgorithms:
            logger.debug(algorithm)
        logger.debug(signedData.contentInfo)

        spcidc = signedData.contentInfo.content
        logger.debug("spcIndirectDataContent.data: %s" % spcidc.data)

        logger.debug("spcIndirectDataContent.data.type: %s" % spcidc.data.type)
        logger.debug("spcIndirectDataContent.data.value: %s" % spcidc.data.value)
        logger.debug("spcIndirectDataContent.messageDigest: %s" % spcidc.messageDigest)

        sourceHash = spcidc.messageDigest.digest
        # print("sourceHash is %s" % hexlify(sourceHash))

        digestAlgorithm = spcidc.messageDigest.digestAlgorithm
        signatureClass = VbaProjectSignature.get_class(SignatureKind.LEGACY)
        contentHash =  oxml.contentHash(signatureClass, digestAlgorithm)

        if contentHash.digest() != sourceHash:
            print("Hash mismatch:")
            print("In signature: %s" % hexlify(sourceHash))
            print("Computed:     %s" % hexlify(contentHash.digest()))
        else:
            print("Hash match!!! %s" % hexlify(sourceHash))

    if oxml.has_signed_macros_agile:
        logger.debug("================ Agile signature ==================")
        print("=================== Agile signature ======================")
        signature = oxml.get_signature(SignatureKind.AGILE)
        signature.analyze()
        logger.debug("Loaded Agile signature")
        signedData = signature.signature.content
        for algorithm in signedData.digestAlgorithms:
            logger.debug(algorithm)
        logger.debug(signedData.contentInfo)

        spcidc = signedData.contentInfo.content
        logger.debug("spcIndirectDataContent.data: %s" % spcidc.data)

        logger.debug("spcIndirectDataContent.data.type: %s" % spcidc.data.type)
        logger.debug("spcIndirectDataContent.data.value: %s" % spcidc.data.value)
        logger.debug("spcIndirectDataContent.messageDigest: %s" % spcidc.messageDigest)

        compiledHash = spcidc.messageDigest.digest_parsed.compiledHash
        # print("compiledHash is %s" % hexlify(compiledHash))
        sourceHash = spcidc.messageDigest.digest_parsed.sourceHash
        # print("sourceHash is %s" % hexlify(sourceHash))

        digestAlgorithm = spcidc.messageDigest.digestAlgorithm
        signatureClass = VbaProjectSignature.get_class(SignatureKind.AGILE)
        contentHash =  oxml.contentHash(signatureClass, digestAlgorithm)

        if contentHash.digest() != sourceHash:
            print("Hash mismatch:")
            print("In signature: %s" % hexlify(sourceHash))
            print("Computed:     %s" % hexlify(contentHash.digest()))
        else:
            print("Hash match!!! %s" % hexlify(sourceHash))
       
    if oxml.has_signed_macros_v3:
        logger.debug("================= V3 signature ====================")
        print("=================== V3 signature =========================")
        signature = oxml.get_signature(SignatureKind.V3)
        signature.analyze()
        logger.debug("Loaded V3 signature")
        signedData = signature.signature.content
        for algorithm in signedData.digestAlgorithms:
            logger.debug(algorithm)
        logger.debug(signedData.contentInfo)

        spcidc = signedData.contentInfo.content
        logger.debug("spcIndirectDataContent.data: %s" % spcidc.data)

        logger.debug("spcIndirectDataContent.data.type: %s" % spcidc.data.type)
        logger.debug("spcIndirectDataContent.data.value: %s" % spcidc.data.value)
        logger.debug("spcIndirectDataContent.messageDigest: %s" % spcidc.messageDigest)

        if spcidc.messageDigest.digest_parsed:
            logger.debug(spcidc.messageDigest.digest_parsed.algorithmId)

        compiledHash = spcidc.messageDigest.digest_parsed.compiledHash
        # print("compiledHash is %s" % hexlify(compiledHash))
        sourceHash = spcidc.messageDigest.digest_parsed.sourceHash
        # print("sourceHash is %s" % hexlify(sourceHash))

        digestAlgorithm = spcidc.messageDigest.digestAlgorithm
        signatureClass = VbaProjectSignature.get_class(SignatureKind.V3)
        contentHash =  oxml.contentHash(signatureClass, digestAlgorithm)

        if contentHash.digest() != sourceHash:
            print("Hash mismatch:")
            print("In signature: %s" % hexlify(sourceHash))
            print("Computed:     %s" % hexlify(contentHash.digest()))
        else:
            print("Hash match!!! %s" % hexlify(sourceHash))

    else:
        print("vbaProject has no signatures")

def load_private_key(private_key_bytes):
    while True:
        password = getpass.getpass('Contraseña para la clave privada: ')
        if len(password):
            password = password.encode('utf8')
        else:
            password = None
        try:
            private_key = serialization.load_pem_private_key(private_key_bytes, password)
            return
        except TypeError:
            sys.stderr.write('La clave privada está protegida por contraseña\n')
        except ValueError:
            sys.stderr.write('La contraseña es incorrecta\n')
            continue

    return private_key

def main():

    parser = argparse.ArgumentParser(
        description="main program to handle Office macro signatures",
    )

    parser.add_argument('command',
                        type=str,
                        help='Command to execute',
                        )
                        
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Show debug information',
                        )

    parser.add_argument('-i', '-in', '--input',
                        type=str,
                        help='Path to input Office file',
                        )

    parser.add_argument('-o', '-out', '--output',
                        type=str,
                        help='Path to output Office file, if neecessary',
                        )

    parser.add_argument('-s', '--signer',
                        type=str,
                        help='Path to signer certificate',
                        )

    parser.add_argument('-k', '--private-key',
                        type=str,
                        help='Path to signer certificate',
                        )
    
    parser.add_argument('--vault-key',
                        type=str,
                        help='Path to transit key in vault',
                        )
    
    args = parser.parse_args()

    if args.debug:
        logger.parent.setLevel(logging.DEBUG)

    input_filename = args.input
    output_filename = args.output

    command = args.command

    if command == 'analyze':
        if not input_filename or output_filename:
            if not input_filename:
                print("No input file")
            if output_filename:
                print("Spurious output file")
            usage()
            sys.exit(1)
        analyze(input_filename)

    elif command == 'verify':
        oxml = OfficeOpenXML(input_filename)
        logger.debug("Loaded OfficeOpenXML from %s" % input_filename)
        
        if not oxml.has_macros:
            print("El archivo %s no tiene macros" % input_filename)
            return

        if not oxml.has_signed_macros:
            print("ERROR: Las macros no están firmadas en {}".format(input_filename))
            return

        result = oxml.verify_signatures()
        if result:
            print("Las firmas son correctas en {}".format(input_filename))
        else:
            print("ERROR: Las firmas no son correctas en {}".format(input_filename))

    elif command == 'analyze-normalized-v3':
        data = open(input_filename, 'rb').read()
        vbaProject.V3ContentHash_analyze(data, 'aa')

    elif command == 'sign':
        oxml = OfficeOpenXML(input_filename, mode='a')
        logger.debug("Loaded OfficeOpenXML from %s" % input_filename)
        
        if not oxml.has_macros:
            print("El archivo %s no tiene macros" % input_filename)
            return

        signer_kind = 'file'
        # signer = vault_signer.get_signer(<path-to-key-in-vault>, <…>)
        if not args.signer:
            print("Se precisa indicar certificado")
            return
        cert_bytes = open(args.signer, 'rb').read()
        try:
            certificate = x509.load_der_x509_certificate(cert_bytes)
        except ValueError:
            certificate = x509.load_pem_x509_certificate(cert_bytes)

        certificates = [certificate]
        if signer_kind == 'file':
            if not args.private_key:
                print("Se precisa indicar clave privada")
                return
            signer_engine = PrivateKeySignerEngine(certificates=certificates)
            signer_engine.load_private_key(private_key_path=args.private_key)
        elif signer_kind == 'vault':
            signer_engine = VaultSignerEngine(certificates=certificates)
            signer_engine.set_parameters(auth='token', key_path=args.vault_key, certificates=certificates)
        oxml.sign_macros(certificates=certificates, signer_engine=signer_engine, output_filename=output_filename)
        # oxml.save(output_filename)
     
    else:
        print("Error invalid command {}".format(command))

main()
