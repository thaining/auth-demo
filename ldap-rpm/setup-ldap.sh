#!/bin/bash

steps_completed=()
raw_temp_password="tempadminpass"
temp_password="${raw_temp_password}"
tmp_workdir="$(mktemp -d -p/tmp $(basename $0)_XXXXX)"
dry_run_mode="0"
force_mode="0"
step_mode="0"
log_mode="0"
ldap_setup_version="1"


setupBaseEnvironment() {
    cat << EOF
export LDAP_DOMAIN_DN="${LDAP_DOMAIN_DN:-dc=example,dc=org}"
export LDAP_ORG="${LDAP_ORG:-Example Organization}"
export LDAP_LIB_PATH="${LDAP_LIB_PATH:-/usr/lib64/openldap}"
export LDAP_DB_NUM="${LDAP_DB_NUM:-2}"
export LDAP_DB_TYPE="${LDAP_DB_TYPE:-mdb}"
export LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-NO_PASSWORD}" # this requires a {SSHA} encoded password
export LDAP_SETUP_FILE="${LDAP_SETUP_FILE:-/etc/openldap/setup_complete}"
export LDAP_USERS="${LDAP_USERS:-user01,user02}"
export LDAP_PASSWORDS="${LDAP_PASSWORDS:-bitnami1,bitnami2}"
export LDAP_READER_GROUP="${LDAP_READER_GROUP:-dbReaders}"
export LDAP_WRITER_GROUP="${LDAP_WRITER_GROUP:-dbWriters}"
export LDAP_ADMIN_GROUP="${LDAP_ADMIN_GROUP:-administrators}"
# these default to the value of ${LDAP_USERS} but that expansion does not work here
export LDAP_DB_READERS="${LDAP_DB_READERS:-user01,user02}"
export LDAP_DB_WRITERS="${LDAP_DB_WRITERS:-user01,user02}"
export LDAP_ADMINS="${LDAP_ADMINS:-user01,user02}"
EOF
}

addModifyExternal() {
    # arguments:
    # 1 - command
    # 2 - LDIF file
    # 3 - log file

    if [ "0" = "$dry_run_mode" ]; then
        "${1}" -Q -Y EXTERNAL -H ldapi:/// -f "${2}" >> "${3}" 2>&1
    else
        echo "${1} -Q -Y EXTERNAL -H ldapi:/// -f ${2} >> ${3} 2>&1" >> ${3}
    fi

    return $?
}

ldapmodifyExternal() {
    # arguments:
    # 1 - LDIF file
    # 2 - log file

    addModifyExternal "ldapmodify" "$@"

    return $?
}

ldapaddExternal() {
    # arguments:
    # 1 - LDIF file
    # 2 - log file

    addModifyExternal "ldapadd" "$@"

    return $?
}


ldapmodifyAdmin() {
    # arguments:
    # 1 - LDIF file
    # 2 - log file
    # 3 - domain dn
    # 4 - password

    if [ "0" = "$dry_run_mode" ]; then
        ldapmodify -x -w ${4} -H ldapi:/// -D cn=admin,${3} -f ${1} >> ${2} 2>&1
    else
        echo "ldapmodify -x -w ${4} -H ldapi:/// -D cn=admin,${3} -f ${1} >> ${2} 2>&1" >> ${2}
    fi
}

encryptPassword() {
    slappasswd -h '{SSHA}' -n -s "${1}"
}

ldap_user_validate() {
    # validate settings in AUTH_LDAP_* env vars
    local error_code=0
    local usernames=($(tr ',;' ' ' <<< "${LDAP_USERS}"))
    local passwords=($(tr ',;' ' ' <<< "${LDAP_PASSWORDS}"))

    if [ "${#usernames[@]}" != "${#passwords[@]}" ]; then
        echo "Number of LDAP users does not match number of LDAP passwords";
        error_code=1
    fi

    local users=($(tr ',;' ' ' <<< "${LDAP_DB_READERS}"))
    users+=($(tr ',;' ' ' <<< "${LDAP_DB_WRITERS}"))
    users+=($(tr ',;' ' ' <<< "${LDAP_ADMINS}"))
    OLD_IFS="$IFS"; IFS=$'\n' users=($(sort -u <<<"${users[*]}")); IFS="$OLD_IFS"

    for user in "${users[@]}"; do
        if [[ ! "${LDAP_USERS}" =~ "${user}" ]]; then
            echo "Reader/writer/admin user '${user}' not in ${LDAP_USERS}"
            error_code=1
        fi
    done

    [[ "$error_code" -eq 0 ]] || exit "$error_code"
}

steps_completed[1]=0
step1() {
    # install openldap packages
    # not implemented
    steps_completed[1]=1
}

steps_completed[2]=0
step2() {
    # encrypt temp password (actual password is already encrypted)
    local ret_code=1

    if [ "0" = "$dry_run_mode" ]; then
        temp_password="$(encryptPassword "$temp_password")"
        ret_code=$?
    else
        temp_password="{SSHA}thisisnotapassword"
    fi

    [ "0" = "$ret_code" ] && steps_completed[2]=1
}

steps_completed[3]=0
step3() {
    # enable operating system services

    systemctl enable slapd.service && \
        systemctl restart slapd.service && \
        steps_completed[3]=1
}

steps_completed[4]=0
step4() {
    # change the domain DN and password of the configuration
    local output_file="${tmp_workdir}/step3.ldif"
    local log_file="${tmp_workdir}/step3.log"
    cat > ${output_file} << EOF
dn: olcDatabase={2}${LDAP_DB_TYPE},cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=admin,${LDAP_DOMAIN_DN}

dn: olcDatabase={2}${LDAP_DB_TYPE},cn=config
changetype: modify
replace: olcSuffix
olcSuffix: ${LDAP_DOMAIN_DN}

dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to *
  by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" read
  by dn.base="cn=admin,${LDAP_DOMAIN_DN}" read
  by * none

dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: ${temp_password}

dn: olcDatabase={2}${LDAP_DB_TYPE},cn=config
changetype: modify
add: olcRootPW
olcRootPW: ${temp_password}
EOF

    ldapmodifyExternal "$output_file" "$log_file" && steps_completed[4]=1
}

steps_completed[5]=0
step5() {
    # install extra LDIF schemas
    local nis_files=('/etc/openldap/schema/cosine.ldif'
                     '/etc/openldap/schema/inetorgperson.ldif'
                     '/etc/openldap/schema/nis.ldif')
    local output_file="${tmp_workdir}/step5.ldif"
    local log_file="${tmp_workdir}/step5.log"
    local schema_count=0

    for file in "${nis_files[@]}"; do
        echo "#" >> "$log_file"
        echo "# adding schema $log_file" >> "$log_file"
        echo "#" >> "$log_file"
        ldapaddExternal "$file" "$log_file" && \
            schema_count=$((schema_count+1))
    done

    [ "3" = "$schema_count" ] && steps_completed[5]=1
}

steps_completed[6]=0
step6() {
    # install the memberof module
    local output_file="${tmp_workdir}/step6.ldif"
    local log_file="${tmp_workdir}/step6.log"

    cat > "$output_file" << EOF
dn: cn=module,cn=config
changetype: add
cn: module
objectclass: olcModuleList
objectclass: top
olcmoduleload: memberof.la
olcmodulepath: ${LDAP_LIB_PATH}

dn: olcOverlay=memberof,olcDatabase={${LDAP_DB_NUM}}${LDAP_DB_TYPE},cn=config
changetype: add
objectClass: olcConfig
objectClass: olcMemberOf
objectClass: olcOverlayConfig
objectClass: top
olcOverlay: memberof
olcMemberOfGroupOC: groupOfUniqueNames
olcMemberOfMemberAD: uniqueMember
EOF

    ldapmodifyExternal "$output_file" "$log_file" && steps_completed[6]=1
}

steps_completed[7]=0
step7() {
    # install the refint module
    local output_file="${tmp_workdir}/step7.ldif"
    local output_file2="${tmp_workdir}/step7-2.ldif"
    local log_file="${tmp_workdir}/step7.log"

    cat > "$output_file" << EOF
dn: cn=module,cn=config
changetype: add
cn: module
objectclass: olcModuleList
objectclass: top
olcmoduleload: refint.la
olcmodulepath: ${LDAP_LIB_PATH}

dn: olcOverlay=refint,olcDatabase={${LDAP_DB_NUM}}${LDAP_DB_TYPE},cn=config
changetype: add
objectClass: olcConfig
objectClass: olcOverlayConfig
objectClass: olcRefintConfig
objectClass: top
olcOverlay: refint
olcRefintAttribute: memberof member manager owner
EOF

    ldapmodifyExternal "$output_file" "$log_file" && steps_completed[7]=1
}

steps_completed[8]=0
step8() {
    # create the schema
    local output_file="${tmp_workdir}/step8.ldif"
    local log_file="${tmp_workdir}/step8.log"
    local first_dn="${LDAP_DOMAIN_DN#dc=}"
    first_dn="${first_dn%%,*}"

    cat > "$output_file" << EOF
dn: ${LDAP_DOMAIN_DN}
changetype: add
objectClass: domain
dc: ${first_dn}
description: ${LDAP_ORG}

dn: ou=People,${LDAP_DOMAIN_DN}
changetype: add
ou: People
objectClass: organizationalUnit
objectClass: top

dn: ou=Groups,${LDAP_DOMAIN_DN}
changetype: add
ou: Groups
objectClass: organizationalUnit
objectClass: top

dn: cn=${LDAP_ADMIN_GROUP},ou=Groups,${LDAP_DOMAIN_DN}
changetype: add
cn: ${LDAP_ADMIN_GROUP}
objectClass: groupOfUniqueNames
objectClass: top
uniqueMember:

dn: cn=${LDAP_READER_GROUP},ou=Groups,${LDAP_DOMAIN_DN}
changetype: add
cn: ${LDAP_READER_GROUP}
objectClass: groupOfUniqueNames
objectClass: top
uniqueMember:

dn: cn=${LDAP_WRITER_GROUP},ou=Groups,${LDAP_DOMAIN_DN}
changetype: add
cn: ${LDAP_WRITER_GROUP}
objectClass: groupOfUniqueNames
objectClass: top
uniqueMember:
EOF

    ldapmodifyAdmin "$output_file" "$log_file" "$LDAP_DOMAIN_DN" "$raw_temp_password" &&
        steps_completed[8]=1
}

steps_completed[9]=0
step9() {
    # set access levels
    local output_file="${tmp_workdir}/step9.ldif"
    local log_file="${tmp_workdir}/step9.log"

    cat > "$output_file" << EOF
dn: olcDatabase={2}${LDAP_DB_TYPE},cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange
  by dn="cn=admin,${LDAP_DOMAIN_DN}" write
  by group/groupOfUniqueNames/uniqueMember="cn=${LDAP_ADMIN_GROUP},ou=Groups,${LDAP_DOMAIN_DN}" write
  by anonymous auth
  by self write
  by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to *
  by self write
  by dn="cn=admin,${LDAP_DOMAIN_DN}" write
  by group/groupOfUniqueNames/uniqueMember="cn=${LDAP_ADMIN_GROUP},ou=Groups,${LDAP_DOMAIN_DN}" write
  by * read
olcAccess: {3}to dn.subtree="ou=People,${LDAP_DOMAIN_DN}"
  by dn="cn=admin,${LDAP_DOMAIN_DN}" write
  by group/groupOfUniqueNames/uniqueMember="cn=${LDAP_ADMIN_GROUP},ou=Groups,${LDAP_DOMAIN_DN}" write
  by anonymous auth
  by self write
  by * none
EOF

    ldapmodifyExternal "$output_file" "$log_file" && steps_completed[9]=1
}

steps_completed[10]=0
step10() {
    # add LDAP users
    local output_file="${tmp_workdir}/step10.ldif"
    local log_file="${tmp_workdir}/step10.log"
    local usernames=($(tr ',;' ' ' <<< "${LDAP_USERS}"))
    local passwords=($(tr ',;' ' ' <<< "${LDAP_PASSWORDS}"))

    for (( i=0; i<${#usernames[@]}; i++)); do
        encrypted_password="$(encryptPassword "${passwords[i]}")"
        cat >> "${output_file}" << EOF
dn: userid=${usernames[i]},ou=People,${LDAP_DOMAIN_DN}
changetype: add
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
userPassword: ${encrypted_password}
sn: Name
cn: User ${usernames[i]}

EOF
    done

    if [ "${#usernames[@]}" -gt "0" ]; then
        ldapmodifyAdmin "$output_file" "$log_file" "$LDAP_DOMAIN_DN" "$raw_temp_password" &&
            steps_completed[10]=1
    else
        steps_completed[10]=1
    fi
}

update_group() {
    local output_file="${1}"
    local group_dn="${2}"
    local people_dn="${3}"
    local -n user_list="${4}"
    local changetype_op="modify"
    local object_op="replace"

    for user in "${user_list[@]}"; do
        cat >> "${output_file}" << EOF
dn: ${group_dn}
changetype: ${changetype_op}
${object_op}: uniqueMember
uniqueMember: cn=${user},${people_dn}

EOF

        [ "replace" = "${object_op}" ] && object_op="add"
    done
}

steps_completed[11]=0
step11() {
    # add LDAP users
    local output_file="${tmp_workdir}/step11.ldif"
    local log_file="${tmp_workdir}/step11.log"
    local db_reader_users=($(tr ',;' ' ' <<< "${LDAP_DB_READERS}"))
    local db_writer_users=($(tr ',;' ' ' <<< "${LDAP_DB_WRITERS}"))
    local admin_users=($(tr ',;' ' ' <<< "${LDAP_ADMINS}"))
    local reader_group_dn="cn=${LDAP_READER_GROUP},ou=Groups,${LDAP_DOMAIN_DN}"
    local writer_group_dn="cn=${LDAP_WRITER_GROUP},ou=Groups,${LDAP_DOMAIN_DN}"
    local admin_group_dn="cn=${LDAP_ADMIN_GROUP},ou=Groups,${LDAP_DOMAIN_DN}"
    local people_dn="ou=People,${LDAP_DOMAIN_DN}"

    update_group "$output_file" "$reader_group_dn" "$people_dn" db_reader_users
    update_group "$output_file" "$writer_group_dn" "$people_dn" db_writer_users
    update_group "$output_file" "$admin_group_dn" "$people_dn" admin_users

    if [ "${#db_reader_users[@]}" -gt "0" ] || [ "${#db_writer_users[@]}" -gt "0" ] || \
      [ "${#admin_users[@]}" -gt "0" ]; then
       ldapmodifyAdmin "$output_file" "$log_file" "$LDAP_DOMAIN_DN" "$raw_temp_password" && \
           steps_completed[11]=1
    else
       steps_completed[11]=1
    fi
}

steps_completed[12]=0
step12() {
    # install the actual pre-encrypted password provided by environment variable
    local output_file="${tmp_workdir}/step12.ldif"
    local log_file="${tmp_workdir}/step12.log"

    # TODO: this is mostly the same template as step3 - refactor both
    cat > "$output_file"  << EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: ${LDAP_ADMIN_PASSWORD}

dn: olcDatabase={2}${LDAP_DB_TYPE},cn=config
changetype: modify
replace: olcRootPW
olcRootPW: ${LDAP_ADMIN_PASSWORD}
EOF

    ldapmodifyExternal "$output_file" "$log_file" && steps_completed[12]=1
}

steps_completed[13]=0
step13() {
    # TLS configuration
    # not currently implemented

    steps_completed[13]=1
}

help() {
    echo "Syntax $0 [-d] [-s [step[,step...]"
    echo "Options:"
    echo "-d      Dry-run mode -- print commands and LDIF, don't run them"
    echo "-f      Force mode -- ignore previous completion checks"
    echo "-s      Step mode -- run comma separated list of steps not all"
    echo "-l      Log mode -- show step logs"
    echo "-c      Config file mode -- use a config file with a setupEnvironment function to set environment variables"
}

steps=()
sorted_steps=()
all_steps=("1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13")

while [ $# -gt 0 ]; do
    cmd=$1
    case "$cmd" in
        -d|--dry-run)   dry_run_mode=1;;
        -f|--force)     force_mode=1;;
        -s|--step-mode) step_mode=1; OLD_IFS=${IFS}; IFS=','; read -ra steps <<< "$2"; \
                        shift; IFS=${OLD_IFS};;
        -l|--log-mode)  log_mode=1;;
        -c|--config-file) config_file=$2; shift;;
        -h|--help)  help; exit 0;;
        *) echo "invalid argument"; help; exit 1;;
    esac
    shift
done

if [ "0" = "$force_mode" ] && [ -f "$LDAP_SETUP_FILE" ]; then
    if [ ! -r "$LDAP_SETUP_FILE" ]  && [ ! -w "$LDAP_SETUP_FILE" ]; then
        echo "LDAP setup file ${LDAP_SETUP_FILE} exists but is not readable or writable"
        echo "Exiting..."
        help
        exit 1
    fi
    prev_setup_version="$(cat ${LDAP_SETUP_FILE})"

    # in future this comparison can be used to handle upgrades
    if (( "$ldap_setup_version" <= "$prev_setup_version" )); then
        echo "$0 version ${ldap_setup_version} is not newer than the previously installed ${prev_setup_version}"
        echo "Exiting..."
        help
        exit 1
    fi
fi

if [ -n "$config_file" ]; then
    if [ ! -f "$config_file" ]; then
        echo "Config file ${config_file} specified but file does not exist"
        echo "Exiting..."
        help
        exit 1
    fi
    if [ ! -r "$config_file" ]; then
        echo "Config file ${config_File} specified but file is not readable"
        echo "Exiting..."
        help
        exit 1
    fi

    . "$config_file"
    eval "$(setupEnvironment)"
fi

# this catches anything not included in setupEnvironment
eval "$(setupBaseEnvironment)"


if [ "0" = "$dry_run_mode" ] && [[ ! "$LDAP_ADMIN_PASSWORD" =~ \{SSHA\}.* ]]; then
   echo "No encrypted password supplied in LDAP_ADMIN_PASSWORD"
   echo "Exiting..."
   help
   exit 1
elif [[ "$LDAP_ADMIN_PASSWORD" =~ \{SSHA\}.* ]]; then
    echo "encrypted password $LDAP_ADMIN_PASSWORD detected in LDAP_ADMIN_PASSWORD"
fi

ldap_user_validate

if [ 0 != "${#steps[@]}" ]; then
    for step in "${steps[@]}"; do
        if [[ "$step" =~ ^step[0-9]+$ ]]; then
            sorted_steps+=("${step##step}")
        fi
    done

    OLD_IFS="$IFS"
    IFS=$'\n'
    sorted_steps=($(sort -n <<<"${sorted_steps[*]}"))
    IFS="$OLD_IFS"

else
    sorted_steps+=("${all_steps[@]}")
fi

step_count="${#sorted_steps}"

for step_number in "${sorted_steps[@]}"; do
    step_log_file=${tmp_workdir}/step${step_number}.log
    eval "step${step_number}"
    if [ "1" == "$log_mode" ] && [ -f ${step_log_file} ]; then
        echo "# printing ${step_log_file}"
        cat "${step_log_file}"
    fi
done

done_step_count=0

for step_done in "${all_steps[@]}"; do
    if [ "1" = "${steps_completed[$step_done]}" ]; then
        done_step_count=$((${done_step_count} + 1))
    fi
done

if [ "$done_step_count" = "${#sorted_steps[@]}" ]; then
    rm -rf ${tmp_workdir}
fi


if [ "$done_step_count" = "${#all_steps[@]}" ]; then
    echo "LDAP setup complete - updating setup file"
    echo "$ldap_setup_version" > "${LDAP_SETUP_FILE}"
fi
