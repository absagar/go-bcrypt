#! /bin/env sh
#
# Update the py-bcrypt components of bcrypt.
#

tag="tip"
hg clone --rev $tag https://py-bcrypt.googlecode.com/hg/py-bcrypt

for i in bcrypt.c blowfish.c pybc_blf.h; do
	diff -q $i py-bcrypt/bcrypt/$i
	if [ $? -ne 0 ]; then
		echo "updating: $i"
		cp py-bcrypt/bcrypt/$i $i
	fi
done

rm -rf py-bcrypt
