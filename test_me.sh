#!/bin/bash
TEST_PATH="."
#~ 				1		2		3		4		5		6		7		8		9		10		11		12		13		14		15		16
params=("NULL"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo" \
						"foo"	"foo"	"foo"	"omer"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo"	"foo")
#~						17		18		19		20		21		22		23		24		25		26		27		28		29		30
timeout 20s ./prf $(echo ${params[$1]}) "program${1}.out" \
			 > studout.txt

diff "out${1}.txt" studout.txt
