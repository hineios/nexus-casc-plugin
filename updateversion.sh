#!/usr/bin/env bash
set -ueo pipefail;

newversion=
while [ "${newversion}" = "" ]; do
    read -p "What is the new Nexus OSS version (example: 3.41.0-01) ? " newversion
done

oldversion=$(grep '<nexus.pkg.version>[0-9]' pom.xml|sed -e 's/ //g' -e 's/<\(\/\)\?nexus.pkg.version>//g')

echo "Replacing version ${oldversion} with new one: ${newversion} ..."

oldversionshort=${oldversion%%-*}
newversionshort=${newversion%%-*}

sed -i -e "s/${oldversion}/${newversion}/g" -e "s/${oldversionshort}/${newversionshort}/g" pom.xml README.md examples/.env
if ! [ -d "target" ]; then
    mkdir target
fi
cd target
../mvnrepo/mvninstall.sh ${newversion}
cd ..
