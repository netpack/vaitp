#!/bin/sh
#This file must be placed in the same folder of the "Attack Injector.jar" file
#It will start the derby database in Client/Server mode
#It will also start the "Attack Injector.jar" application

export CLASSPATH=.lib/derby.jar:lib/derbynet.jar
java org.apache.derby.drda.NetworkServerControl start &
java -jar Attack\ Injector.jar
java org.apache.derby.drda.NetworkServerControl shutdown
