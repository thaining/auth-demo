#!/bin/bash
#
# bootcamp OpenLDAP library

stage2_ldap_env() {
    cat << "EOF"
# Users
export AUTH_LDAP_READER_GROUP="${AUTH_LDAP_READER_GROUP:-db_readers}"
export AUTH_LDAP_WRITER_GROUP="${AUTH_LDAP_WRITER_GROUP:-db_writers}"
export AUTH_LDAP_DB_READERS="${AUTH_LDAP_DB_READERS:-${LDAP_USERS}}"
export AUTH_LDAP_DB_WRITERS="${AUTH_LDAP_DB_WRITERS:-${LDAP_USERS}}"
EOF
}

stage2_ldap_validate() {
    info "Validating settings in AUTH_LDAP_* env vars"
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        error "$1"
        error_code=1
    }

    users=()
    users+=($(tr ',;' ' ' <<< "${AUTH_LDAP_DB_READERS}"))
    users+=($(tr ',;' ' ' <<< "${AUTH_LDAP_DB_WRITERS}"))

    for user in "${users[@]}"; do
        if [[ ! ${LDAP_USERS} =~ ${user} ]]; then
          print_validation_error "Reader/writer user '${user}' not in ${LDAP_USERS}. Make sure that AUTH_LDAP_DB_READERS and AUTH_LDAP_DB_WRITERS contain valid user names."
        fi
    done

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

stage2_modify_tree() {
    output_file="${LDAP_SHARE_DIR}/stage2_tree.ldif"

    cat >> "${output_file}" << EOF
dn: ${AUTH_LDAP_READER_GROUP/#/cn=},${LDAP_USER_DC/#/ou=},${LDAP_ROOT}
changetype: add
objectClass: groupOfNames
cn: ${AUTH_LDAP_READER_GROUP}
EOF

    readers=($(tr ',;' ' ' <<< "${AUTH_LDAP_DB_READERS}"))

    for user in "${readers[@]}"; do
        cat >> "${output_file}" << EOF
member: ${user/#/cn=},${LDAP_USER_DC/#/ou=},${LDAP_ROOT}
EOF
    done

echo "" >> "${output_file}"

    cat >> "${output_file}" << EOF
dn: ${AUTH_LDAP_WRITER_GROUP/#/cn=},${LDAP_USER_DC/#/ou=},${LDAP_ROOT}
changetype: add
objectClass: groupOfNames
cn: ${AUTH_LDAP_WRITER_GROUP}
EOF

    writers=($(tr ',;' ' ' <<< "${AUTH_LDAP_DB_WRITERS}"))

    for user in "${writers[@]}"; do
        cat >> "${output_file}" << EOF
member: ${user/#/cn=},${LDAP_USER_DC/#/ou=},${LDAP_ROOT}
EOF
    done

    debug_execute ldapmodify -f "${output_file}" -H "ldapi:///" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD"
}

stage2_ldap_initialize() {
    info "Starting stage2 initialize"
    local to_start=is_ldap_running

    $to_start || ldap_start_bg
    if ! is_boolean_yes "$LDAP_SKIP_DEFAULT_TREE"; then
        stage2_modify_tree
    fi
    $to_start || ldap_stop
}
