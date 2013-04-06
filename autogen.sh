#! /bin/sh

PROGRAM="libcurvecpr"

SCRIPT=$( basename $0 )
ERROR=0

error() {
    MESSAGE=$1
    echo "error: ${MESSAGE}"

    ERROR=1
}

hint() {
    MESSAGE=$1
    echo "hint: ${MESSAGE}"
}

status() {
    MESSAGE=$1
    echo "${SCRIPT}: ${MESSAGE}"
}

die_if_error() {
    if [ $ERROR -ne 0 ]; then
        exit 1
    fi
}

( autoconf --version >/dev/null 2>&1 ) || {
    error "The \`autoconf\` program must be installed to compile ${PROGRAM}."
}

( automake --version >/dev/null 2>&1 ) || {
    error "The \`automake\` program must be installed to compile ${PROGRAM}."
}

( aclocal --version >/dev/null 2>&1 ) || {
    error "The \`aclocal\` program must be installed to compile ${PROGRAM}."
    hint "\`aclocal\` is usually provided by \`automake\`. Is your version of \`automake\`"
    hint "up to date?"
}

( libtool --version >/dev/null 2>&1 ) || {
    error "The \`libtool\` program must be installed to compile ${PROGRAM}."
}

( libtoolize --version >/dev/null 2>&1 ) || {
    error "The \`libtoolize\` program must be installed to compile ${PROGRAM}."
    hint "\`libtoolize\` is usually provided by \`libtool\`. Is your version of \`libtool\`"
    hint "up to date?"
}

( pkg-config --version >/dev/null 2>&1 ) || {
    error "The \`pkg-config\` program must be installed to compile ${PROGRAM}."
}

die_if_error

status "Running libtoolize"
( libtoolize --force --copy ) || {
     error "libtoolize failed"
     exit 1
}

status "Running aclocal"
( aclocal ) || {
    error "aclocal failed"
    exit 1
}

status "Running autoheader"
( autoheader ) || {
    error "autoheader failed"
    exit 1
}

status "Running automake"
( automake --add-missing ) || {
    error "automake failed"
    exit 1
}

status "Running autoconf"
( autoconf ) || {
    error "autoconf failed"
    exit 1
}
