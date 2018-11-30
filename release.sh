#!/usr/bin/env bash
export JAVA_HOME=`/usr/libexec/java_home -v 1.8`
export PATH=JAVA_HOME/bin:$PATH

read -p "Really deploy to GitHub releases (Y/N)? "
if ( [ "$REPLY" == "Y" ] ) then

  mvn clean package
  mvn github-release:release

else
  echo -e "Exit without deploy"
fi