#!/bin/sh

## General Configuration

export PYTHONPATH=../zokin:../zokin/ZnaKes
PYTHON_BIN=../zokin/env/bin/python3
ZOKIN="$PYTHON_BIN ../zokin/run.py"
ZOKINFILE="./zokinfile.json"


## Zokinfile Variables

# ZF_DOC_RISK_REPORT="lastenheftPhase.attestedDocuments.0.document"
# ZF_DOC_RISK_REPORT_ATT0="lastenheftPhase.attestedDocuments.0.attestations.0"


keygen () {
    $ZOKIN gen -t keypair-babyjubjub "" \
        | $ZOKIN zokinfile \
        --to "field:$1.privateKey field:$1.publicKey.x field:$1.publicKey.y" \
        --create  --save --file $ZOKINFILE -
}

set_val () {
    $ZOKIN zokinfile -s $1 --save --create $2
}

set_typed_val () {
    set_val $1:$2 $3
}

set_pointer () {
    $ZOKIN zokinfile -s pointer:$1 --save $2
}

set_hex() {
    set_typed_val hex $1 $2
}

generate_document() {
    local phase=$1
    local name=$2
    local doctype=$3
    local dest_document_index=$4
    local identifier=$($ZOKIN gen -t field "" | $ZOKIN convert -f field -t hex -)
    local reference="0000000000000000000000000000000000000000000000000000000000000000"

    local key=document.$name
    local dest_key=${phase}docs[$dest_document_index].document

    $ZOKIN zokinfile -s hex:$key.identifier  --save --create $identifier
    set_pointer $dest_key.identifier $key.identifier

    $ZOKIN zokinfile -s hex:$key.documentType --save --create $doctype
    set_pointer $dest_key.documentType $key.documentType

    $ZOKIN zokinfile -s hex:$key.referenceDocument --save --create $reference
    set_pointer $dest_key.referenceDocument $key.referenceDocument

    local document=$doctype$identifier$reference
    echo $document
}

attest() {
    local signer=$1
    local action=$2
    local phase=$3
    local data=$4
    local dest_document_index=$5
    local dest_attestation_index=$6
    local doc_key="$phase[$dest_document_index].document"
    local att_key="$phase[$dest_document_index].attestations.$dest_attestation_index"

    echo `$ZOKIN zokinfile -g $signer.privateKey` $action$data  \
        | $ZOKIN gen -t eddsa-signature - \
        | $ZOKIN zokinfile --to \
            "$att_key.signature.Rx $att_key.signature.Ry $att_key.signature.S" \
            --create  --save --file $ZOKINFILE -
    set_pointer $att_key.attestor.role $signer.role
    set_pointer $att_key.attestor.publicKey.x $signer.publicKey.x
    set_pointer $att_key.attestor.publicKey.y $signer.publicKey.y
    set_hex $att_key.action $action
    set_val $att_key.is_set 1

    # Generate padding
    # Generate SHA256 Padding
    # Hash is over Sig.Rx SignerPublic.x DOC_TYPE DOC_IDENTIFIER DOC_REFERENCE 
    local signer_public=$($ZOKIN zokinfile -g $signer.publicKey.x | $ZOKIN c -ffield -thex -)
    local signature_rx=$($ZOKIN zokinfile -g $att_key.signature.Rx | $ZOKIN c -ffield -thex -)
    local padding=$($ZOKIN sha256 -f hex -t u32 -pP $signer_public$signature_rx$action$data)

    $ZOKIN zokinfile -s $doc_key.sha256Padding --save "$padding"
}

# Generate new zokinfile

$ZOKIN gen -f abi -t zokinfile ../zokrates/main.abi > $ZOKINFILE

DOCTYPE_RISKREPORT=00000003
ACTION_APPROVE="00040000"

# Generate root authority key pair
keygen root
keygen operator
set_hex operator.role 0x03030003

DOC_RISKREPORT=$(generate_document lastenheftPhase riskreport $DOCTYPE_RISKREPORT 0)
attest operator $ACTION_APPROVE lastenheftPhase $DOC_RISKREPORT 0 0

## Steps
#
# 1. Apply action document identifier
# 
# # 1. Gen document data
# # Risk Report
# DOC_TYPE="00000003"
# # Random Identifier
# DOC_IDENTIFIER=$($ZOKIN gen -t field "" | $ZOKIN convert -f field -t hex -)
# # References nothing
# DOC_REFERENCE="0000000000000000000000000000000000000000000000000000000000000000"
# # SHA256 Padding
# DOCUMENT=$DOC_TYPE$DOC_IDENTIFIER$DOC_REFERENCE
# 
# # assign to zokinfile fields
# $ZOKIN zokinfile -s hex:$ZF_DOC_RISK_REPORT.identifier --save $DOC_IDENTIFIER
# $ZOKIN zokinfile -s hex:$ZF_DOC_RISK_REPORT.documentType --save "$DOC_TYPE"
# $ZOKIN zokinfile -s hex:$ZF_DOC_RISK_REPORT.referenceDocument --save $DOC_REFERENCE
# 
# echo `$ZOKIN zokinfile -g operator.privateKey` $DOC_ACTION$DOCUMENT  \
#     | $ZOKIN gen -t eddsa-signature - \
#     | $ZOKIN zokinfile --to \
#         "$ZF_DOC_RISK_REPORT_ATT0.signature.Rx $ZF_DOC_RISK_REPORT_ATT0.signature.Ry $ZF_DOC_RISK_REPORT_ATT0.signature.S" \
#         --create  --save --file $ZOKINFILE -

# Generate SHA256 Padding
# Hash is over Sig.Rx SignerPublic.x DOC_TYPE DOC_IDENTIFIER DOC_REFERENCE 
# SIGNER_PUBLICKEY_X=$($ZOKIN zokinfile -g operator.publicKey.x | $ZOKIN c -ffield -thex -)
# SIG_RX=$($ZOKIN zokinfile -g $ZF_DOC_RISK_REPORT_ATT0.signature.Rx | $ZOKIN c -ffield -thex -)
# # 
# DOC_PADDING=$($ZOKIN sha256 -f hex -t u32 -pP $SIGNER_PUBLICKEY_X$SIG_RX$DOC_ACTION$DOCUMENT)
# $ZOKIN zokinfile -s $ZF_DOC_RISK_REPORT.sha256Padding --save "$DOC_PADDING"
# 
# # Last attestation for this document?
# $ZOKIN zokinfile -s $ZF_DOC_RISK_REPORT_ATT0.last --save 0
# 
# # Generate Params
$ZOKIN zokinfile --resolve-pointers --save ""
# # $ZOKIN zokinfile --fill-random --save ""
# 
$ZOKIN gen -f zokinfile  $ZOKINFILE
# # $ZOKIN gen -f zokinfile -
