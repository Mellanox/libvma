#!/bin/bash

echo 'Extracting and applying LWIP patches.'

DIR=$1

if [ ! -d "$DIR" ]; then
	echo "Invalid directory, $DIR."
	exit 1
fi

cd $DIR

for p in $(cat lwip-vma/patches/series); do
	echo "Applying $p."
	if ! patch -d $DIR/lwip -Np1 -i ${DIR}/lwip-vma/patches/$p; then
		echo "Application of $p failed."
		exit 2
	fi
done
