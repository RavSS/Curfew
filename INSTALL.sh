#!/bin/sh
set +x

if [ `id -u` != 0 ]
then
	echo "Please run the installation script as root."
	exit 1
fi

echo "Installation for Curfew has started."
echo "Checking dependencies..."

command -v pkg-config > /dev/null

if [ $? != 0 ]
then
	echo "Please install 'pkg-config' first."
	exit 1
fi

pkg-config --exists libnl-3.0 libnl-genl-3.0

if [ $? != 0 ]
then
	echo "Please install the development libraries"
	echo "for 'libnl-3.0' and 'libnl-genl-3.0' first."
	exit 1
fi


echo "Beginning to make..."

make

if [ $? != 0 ]
then
	echo "Compilation failed. Please report any errors."
	exit 1
fi

make install

if [ $? != 0 ]
then
	echo "Installation failed. Check the Makefile install directory's status."
	exit 1
fi

echo "Curfew is now installed. You can uninstall it via 'sudo make uninstall'."

exit 0
