
#
# stage2 startup file

# load stage2 libraries
. /opt/bitnami/scripts/stage2.sh

# load stage2 environment variables
eval "$(stage2_ldap_env)"

# Ensure stage2 environment variables are valid
stage2_ldap_validate
# Perform stage2 setup steps
stage2_ldap_initialize
