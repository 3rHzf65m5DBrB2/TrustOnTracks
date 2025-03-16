#!/bin/sh

set -e

source ./defs.sh
source ./common.sh

generate_parties () {
    create_party root "$ROLE_ROOT"
    # create_party FRA "$ROLE_ROOT"
    create_party ASBO "$ROLE_ASBO"
    create_party DEBO "$ROLE_DEBO"
    create_party FGV1 "$ROLE_FGV1"
    create_party BAV "$ROLE_BAV"
    create_party FGV2 "$ROLE_FGV2"
    create_party OPERATOR "$ROLE_OPERATOR"

    # Set Root Authority Public Key
    set_pointer rootAuthorityPublicKey.x root.publicKey.x
    set_pointer rootAuthorityPublicKey.y root.publicKey.y
}

generate_documents () {
    generate_document $PHASE_LH $DOC_SA $DOCTYPE_SA 0 > /dev/null
    generate_document $PHASE_LH $DOC_TR $DOCTYPE_TR 1 > /dev/null
    generate_document $PHASE_LH $DOC_PTD1 $DOCTYPE_PTD1 2 > /dev/null
    generate_document $PHASE_LH $DOC_RS $DOCTYPE_RS 3 > /dev/null
    generate_document $PHASE_LH $DOC_SUC $DOCTYPE_SUC 4 > /dev/null
    generate_document $PHASE_LH $DOC_SUC2 $DOCTYPE_SUC2 5 > /dev/null
    generate_document $PHASE_LH $DOC_FGV1 $DOCTYPE_FGV1 6 > /dev/null
    generate_document $PHASE_LH $DOC_FGV2 $DOCTYPE_FGV2 7 > /dev/null
    generate_document $PHASE_LH $DOC_PTD $DOCTYPE_PTD 8 > /dev/null
 
    refdocs $DOC_SUC "$DOC_SUC2"
    refdocs $DOC_PTD "$DOC_SA $DOC_TR $DOC_PTD1 $DOC_RS"
}

make_attestations () {
    attest_role root ASBO $PHASE_LH 0 2
    attest_role ASBO ASBO $PHASE_LH 0 1
    attest_document ASBO $PHASE_LH $DOC_SA 0 0

    attest_role root DEBO $PHASE_LH 1 2
    attest_role DEBO DEBO $PHASE_LH 1 1
    attest_document DEBO $PHASE_LH $DOC_TR 1 0

    attest_role root OPERATOR $PHASE_LH 2 2
    attest_role OPERATOR FGV1 $PHASE_LH 2 1
    attest_document FGV1 $PHASE_LH $DOC_PTD1 2 0

    attest_role root OPERATOR $PHASE_LH 3 2
    attest_role OPERATOR BAV $PHASE_LH 3 1
    attest_document BAV $PHASE_LH $DOC_RS 3 0

    attest_role root OPERATOR $PHASE_LH 4 2
    attest_role OPERATOR BAV $PHASE_LH 4 1
    attest_document BAV $PHASE_LH $DOC_SUC 4 0

    attest_role root OPERATOR $PHASE_LH 5 2
    attest_role OPERATOR FGV2 $PHASE_LH 5 1
    attest_document FGV2 $PHASE_LH $DOC_PTD 5 0

    attest_role root OPERATOR $PHASE_LH 6 2
    attest_role OPERATOR FGV2 $PHASE_LH 6 1
    attest_document FGV2 $PHASE_LH $DOC_SUC2 6 0

    attest_role root root $PHASE_LH 7 2
    attest_role root root $PHASE_LH 7 1
    attest_document root $PHASE_LH $DOC_FGV1 7 0
 
    attest_role root root $PHASE_LH 8 2
    attest_role root root $PHASE_LH 8 1
    attest_document root $PHASE_LH $DOC_FGV2 8 0
}

setup () {
    generate_zokinfile ../abi/lh.abi
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
