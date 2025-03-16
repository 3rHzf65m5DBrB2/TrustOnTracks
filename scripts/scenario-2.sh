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
    generate_document $PHASE_LH $DOC_PTD $DOCTYPE_PTD 1 > /dev/null
}

make_attestations () {
    attest_document operator $PHASE_LH $DOC_RISKREPORT 0 0
    attest_document operator $PHASE_LH $DOC_PTD 1 0
    attest_role root operator $PHASE_LH 0 1
    attest_role root operator $PHASE_LH 1 1
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
