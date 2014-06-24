
# - Find Sodium
# Find the native libsodium includes and library.
# Once done this will define
#
#  CHECK_INCLUDE_DIR    - where to find check header files, etc.
#  CHECK_LIBRARY        - List of libraries when using check
#  CHECK_FOUND          - True if check found.
#

FIND_LIBRARY(CHECK_LIBRARY_CHECK NAMES check HINTS ${CHECK_ROOT_DIR}/lib)
FIND_LIBRARY(CHECK_LIBRARY_COMPAT NAMES compat HINTS ${CHECK_ROOT_DIR}/lib)
find_path(CHECK_INCLUDE_DIR NAMES check.h HINTS ${CHECK_ROOT_DIR}/include)

# handle the QUIETLY and REQUIRED arguments and set SODIUM_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Check REQUIRED_VARS CHECK_LIBRARY_CHECK CHECK_LIBRARY_COMPAT CHECK_INCLUDE_DIR)

SET(CHECK_LIBRARY ${CHECK_LIBRARY_CHECK} ${CHECK_LIBRARY_COMPAT})
MARK_AS_ADVANCED(CHECK_LIBRARY CHECK_INCLUDE_DIR)
