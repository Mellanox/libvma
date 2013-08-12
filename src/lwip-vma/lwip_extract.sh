#!/bin/bash

echo 'Extracting and applying LWIP patches.'

DIR=$1

if [ ! -d "$DIR" ]; then
	echo "Invalid directory, $DIR."
	exit 1
fi

cd $DIR
unzip -q lwip-1.4.0.rc1.zip
mv lwip-1.4.0.rc1 lwip
cp -r lwip-vma/arch  lwip/arch
for i in $(find lwip-vma/ -name Makefile.am); do 
	cp $i ${i/-vma/}
done

for p in $(cat lwip-vma/patches/series); do
	echo "Applying $p."
	if ! patch -d $DIR/lwip -Np1 -i ${DIR}/lwip-vma/patches/$p; then
		echo "Application of $p failed."
		exit 2
	fi
done
