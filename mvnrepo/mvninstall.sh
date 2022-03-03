#!/usr/bin/env bash
set -ueo pipefail;

BASE_DIR="$(cd -P "$(dirname "${0}")" && pwd)";

installFile() {
    local group="${1}";
    local artifact="${2}";
    local version="${3}";
    local dir="${4:-"${BASE_DIR}"}";
    local opts="";

    echo "installing ${group}:${artifact}:${version} ...";
    if [ -f "${dir}/${artifact}.jar" ]; then
        opts="${opts} -Dfile=${dir}/${artifact}.jar";
        if [ -f "${dir}/${artifact}.pom" ]; then
            opts="${opts} -DpomFile=${dir}/${artifact}.pom";
        fi
    else
        if [ -f "${dir}/${artifact}-${version}.jar" ]; then
            opts="${opts} -Dfile=${dir}/${artifact}-${version}.jar";
            if [ -f "${dir}/${artifact}-${version}.pom" ]; then
                opts="${opts} -DpomFile=${dir}/${artifact}-${version}.pom";
            fi
        else
            echo "WARN: No files ${dir}/${artifact}-${version}.jar or ${dir}/${artifact}.jar found. Skipped.";
            return 1;
        fi
    fi

    artifact=$(echo -n "${artifact}" | tr '[:upper:]' '[:lower:]');
    mvn install:install-file  -DgroupId="${group}" -DartifactId="${artifact}" -Dversion="${version}" \
                          ${opts} -Dpackaging=jar -DcreateChecksum=true -DlocalRepositoryPath="${BASE_DIR}";
}


VER="3.38.0-01"

installFile "com.sonatype.nexus" "nexus-licensing-extension" "${VER}";
installFile "com.sonatype.nexus.plugins" "nexus-healthcheck-base" "${VER}";
installFile "com.sonatype.nexus.plugins" "nexus-ldap-plugin" "${VER}";

