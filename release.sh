#!/usr/bin/env bash
export JAVA_HOME=`/usr/libexec/java_home -v 1.8`
export PATH=JAVA_HOME/bin:$PATH

read -p "Really deploy to Maven Central repository and GitHub releases (Y/N)? "
if ( [ "$REPLY" == "Y" ] ) then

  mvn clean
  mvn release:clean
  mvn release:prepare -DupdateWorkingCopyVersions=false
  mvn release:perform -Prelease -X -e | tee release.log
  mvn github-release:release

else
  echo -e "Exit without deploy"
fi