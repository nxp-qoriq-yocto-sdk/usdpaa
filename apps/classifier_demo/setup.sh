#!/bin/sh

MAJOR=`cat /proc/devices | grep "dpa_classifier" | sed -e 's/ .*$//'`
if [ -z "${MAJOR}" ]
then
	echo
	echo "ERROR: Unable to determine the DPA Classifier major device number."
	echo
	exit 1;
fi

echo
echo "INFO: Found DPA Classifier Table major device number: ${MAJOR}"
echo "INFO: Creating filesystem node..."
echo

mknod /dev/dpa_classifier c ${MAJOR} 0

MAJOR=`cat /proc/devices | grep "dpa_stats" | sed -e 's/ .*$//'`
if [ -z "${MAJOR}" ]
then
	echo
	echo "ERROR: Unable to determine the DPA Stats major device number."
	echo
	exit 1;
fi

echo
echo "INFO: Found DPA Stats major device number: ${MAJOR}"
echo "INFO: Creating filesystem node..."
echo

mknod /dev/dpa_stats c ${MAJOR} 0

exit 0;
