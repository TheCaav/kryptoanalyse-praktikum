#!/bin/sh

make clean
make

./vigenere test.txt test.ciph vcnjfkjwufnmkfdgnjd encipher
./vigenere test.ciph test.deciph vcnjfkjwufnmkfdgnjd decipher

cmp --silent test.txt test.deciph && echo "SUCCESS" || echo "Files are different"

./vigenere-attacke

./vigenere testtext.ciph testtext.txt AXFJVOEWJFSAJH decipher
