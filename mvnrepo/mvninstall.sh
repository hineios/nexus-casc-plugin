SRC="."
DST="."
VER="3.37.2-02"
GROUP=com.sonatype.nexus.plugins
ARTIFACT=nexus-ldap-plugin
#ARTIFACT=nexus-healthcheck-base

#GROUP=com.sonatype.nexus
#ARTIFACT=nexus-licensing-extension

mvn install:install-file  -DgroupId=${GROUP} -DartifactId=${ARTIFACT} -Dversion=${VER} \
                          -Dfile=${SRC}/${ARTIFACT}-${VER}.jar -Dpackaging=jar -DgeneratePom=true -DcreateChecksum=true \
                          -DlocalRepositoryPath=${DST}
