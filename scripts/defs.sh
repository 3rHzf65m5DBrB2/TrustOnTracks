#!/usr/bin/bash
#
ZOKIN_PATH=../../zokin
ZNAKES_PATH=../../zokin/ZnaKes
export PYTHONPATH=$ZOKIN_PATH:$ZNAKES_PATH
PYTHON_BIN=$ZOKIN_PATH/env/bin/python3
ZOKIN="$PYTHON_BIN $ZOKIN_PATH/run.py"
ZOKINFILE="./zokinfile.json"

ACTION_ASSIGN=00020000

set -u

zokinfile () {
    $ZOKIN zokinfile -gykPIT all
}

output_params () {
    $ZOKIN zokinfile --resolve-pointers "" > $ZOKINFILE.resolved
    $ZOKIN gen -f zokinfile $ZOKINFILE.resolved
}

generate_zokinfile () {
    abifile=$1
    $ZOKIN gen -f abi -t zokinfile $abifile > $ZOKINFILE
}

keygen () {
    local name=$1
    local keypair=$($ZOKIN gen -t keypair-babyjubjub "")
    echo $keypair \
        | $ZOKIN zokinfile \
        --to "field:$name.privateKey field:$name.publicKey.x field:$name.publicKey.y" \
        --create  --save --file $ZOKINFILE -
    echo $keypair
}

set_val () {
    local key=$1
    local val=$2
    $ZOKIN zokinfile -s $key --save --create $val
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

create_party () {
    local name=$1
    local role=($2)

    local creatable_docs=${role[0]}

    keygen $name > /dev/null
    set_hex $name.role.documentTypes $creatable_docs
}

refdocs () {
    local name=$1
    local targets=($2)
    local target_data=""

    for i in "${targets[@]}"
    do
        local identifier=$($ZOKIN zokinfile -g document.$i.identifier)
        target_data=$target_data$identifier
        # echo $identifier 
    done
    # echo $target_data
    local result=$($ZOKIN sha256 -f hex -t hex $target_data)
    set_val document.$name.referenceDocuments $result
}

generate_document () {
    local phase=$1
    local name=$2
    local doctype=$3
    local dest_document_index=$4
    local identifier=$($ZOKIN gen -t field "" | $ZOKIN convert -f field -t hex -)
    local reference="0000000000000000000000000000000000000000000000000000000000000000"

    local key=document.$name
    local dest_key=${phase}docs[$dest_document_index]

    $ZOKIN zokinfile -s hex:$key.identifier  --save --create $identifier
    set_pointer $dest_key.identifier $key.identifier

    $ZOKIN zokinfile -s hex:$key.documentType --save --create $doctype
    set_pointer $dest_key.documentType $key.documentType

    $ZOKIN zokinfile -s hex:$key.referenceDocuments --save --create $reference
    set_pointer $dest_key.referenceDocuments $key.referenceDocuments

    local document=$doctype$identifier$reference
    echo $document
}

assign_attestor () {
    local source=$1
    local dest=$2
    set_pointer $dest.role.documentTypes $source.role.documentTypes
    set_pointer $dest.publicKey.x $source.publicKey.x
    set_pointer $dest.publicKey.y $source.publicKey.y
}

# no_attest () {
#     local phase=$1
#     local dest_document_index=$2
#     local dest_attestation_index=$3
#     local doc_key="${phase}docs[$dest_document_index]"
#     local att_key="${phase}chains[$dest_document_index][$dest_attestation_index]"
# 
#     echo `$ZOKIN zokinfile -g $signer.privateKey` $action$data  \
#         | $ZOKIN gen -t eddsa-signature - \
#         | $ZOKIN zokinfile --to \
#             "$att_key.signature.Rx $att_key.signature.Ry $att_key.signature.S" \
#             --create  --save --file $ZOKINFILE -
# 
#     assign_attestor $signer $att_key.attestor
#     set_hex $att_key.action $action
#     set_val $att_key.is_set 1
# 
# }

## TODO:
## I am wasting time fixing a non-final structure
## Update the structure to support hidden stuff
## Currently what's broken is for attest role, the sha256padding is set on the
# attestor, rather than the attestee
attest() {
    local attest_type=$1
    local signer=$2
    local phase=$3
    local data=$4
    local dest_document_index=$5
    local dest_attestation_index=$6

    local doc_key="${phase}docs[$dest_document_index]"
    local att_key="${phase}chains[$dest_document_index][$dest_attestation_index]"

    echo `$ZOKIN zokinfile -g $signer.privateKey` $data  \
        | $ZOKIN gen -t eddsa-signature - \
        | $ZOKIN zokinfile --to \
            "$att_key.signature.Rx $att_key.signature.Ry $att_key.signature.S" \
            --create  --save --file $ZOKINFILE -

    assign_attestor $signer $att_key.attestor
    set_val $att_key.is_set 1

    # Generate padding
    # Generate SHA256 Padding
    # Hash is over Sig.Rx SignerPublic.x DOC_TYPE DOC_IDENTIFIER DOC_REFERENCE 
    local signer_public=$($ZOKIN zokinfile -g $signer.publicKey.x | $ZOKIN c -ffield -thex -)
    local signature_rx=$($ZOKIN zokinfile -g $att_key.signature.Rx | $ZOKIN c -ffield -thex -)
    local sha256_input=$signer_public$signature_rx$data

    local padding=$($ZOKIN sha256 -f hex -t u32 -pPF $sha256_input)

    $ZOKIN zokinfile -s $att_key.sha256Padding --save "$padding"
}

attest_role () {
    local signer=$1
    local signee=$2
    local phase=$3
    local dest_document_index=$4
    local dest_attestation_index=$5

    local signee_role=$($ZOKIN zokinfile -g $signee.role.documentTypes)

    local signee_publickey_x=$($ZOKIN zokinfile -g $signee.publicKey.x | $ZOKIN c -ffield -thex -)
    local signee_publickey_y=$($ZOKIN zokinfile -g $signee.publicKey.y | $ZOKIN c -ffield -thex -)

    local signed_data=$signee_role$signee_publickey_x$signee_publickey_y

    attest role $signer $phase $signed_data $dest_document_index $dest_attestation_index
}

attest_document () {
    local signer=$1
    local phase=$2
    local name=$3
    local dest_document_index=$4
    local dest_attestation_index=$5
    
    local key=document.$name
    
    local identifier=$($ZOKIN zokinfile -g $key.identifier)
    local doctype=$($ZOKIN zokinfile -g $key.documentType)
    local reference=$($ZOKIN zokinfile -g $key.referenceDocuments)
    local document=$doctype$identifier$reference

    attest document $signer $phase $document $dest_document_index $dest_attestation_index
}
