#!/bin/sh

set -e

source ./defs.sh
source ./common.sh

generate_parties () {
    create_party root "$ROLE_ROOT"
    create_party operator "$ROLE_OPERATOR"
    # create_party fgv $ROLE_FGV

    # Set Root Authority Public Key
    set_pointer rootAuthorityPublicKey.x root.publicKey.x
    set_pointer rootAuthorityPublicKey.y root.publicKey.y
}

generate_documents () {
    generate_document $PHASE_LH $DOC_RISKREPORT $DOCTYPE_RISKREPORT 0 > /dev/null
    generate_document phase2 phase2doc $DOCTYPE_RISKREPORT 0 > /dev/null
    generate_document phase3 phase3doc0 $DOCTYPE_RISKREPORT 0 > /dev/null
    generate_document phase3 phase3doc1 $DOCTYPE_RISKREPORT 1 > /dev/null
}

make_attestations () {
    attest_document operator $ACTION_APPROVE $PHASE_LH $DOC_RISKREPORT 0 0
    attest_role root operator $PHASE_LH 0 1

    attest_document operator $ACTION_APPROVE phase2 phase2doc 0 0
    attest_role root operator phase2  0 1
    
    attest_document operator $ACTION_APPROVE phase3 phase3doc0 0 0
    attest_role root operator phase3  0 1
 
    attest_document operator $ACTION_APPROVE phase3 phase3doc1 1 0
    attest_role root operator phase3  1 1
}

setup () {
    generate_zokinfile ../zokrates/main.abi
    generate_parties
    generate_documents
}

preparams () {
    setup
    make_attestations
}

full () {
    setup
    make_attestations
    output_params
}

$@
