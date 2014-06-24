########################################################################
# Project setup
########################################################################
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libcurvecpr)
ENABLE_LANGUAGE(C)

# Enable C++ if MSVC is on, it's C compiler sucks and so we need to compile as C++
if (MSVC)
	ENABLE_LANGUAGE(CXX)
endif(MSVC)

SET(LIBCURVECPR_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
SET(LIBCURVECPR_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

# config.h setup
INCLUDE (CheckIncludeFiles)
CONFIGURE_FILE(${LIBCURVECPR_SOURCE_DIR}/lib/config.h.in ${LIBCURVECPR_SOURCE_DIR}/lib/config.h)

# Use a static build if necessary
IF(SODIUM_STATIC)
add_definitions(-DSODIUM_STATIC)
ENDIF(SODIUM_STATIC)

########################################################################
# Dependencies
########################################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Libsodium
find_package(Sodium REQUIRED)

#check
FIND_PACKAGE(Check)

########################################################################
# includes
########################################################################
SET(libcurvecpr_headers
	include/curvecpr.h
	include/curvecpr/block.h
	include/curvecpr/bytes.h
	include/curvecpr/chicago.h
	include/curvecpr/client.h
	include/curvecpr/messager.h
	include/curvecpr/packet.h
	include/curvecpr/server.h
	include/curvecpr/session.h
	include/curvecpr/trace.h
	include/curvecpr/util.h)

INSTALL(FILES ${libcurvecpr_headers} DESTINATION include)

########################################################################
# library
########################################################################
INCLUDE_DIRECTORIES(${LIBCURVECPR_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${SODIUM_INCLUDE_DIR})
SET(libcurvecpr_sources
	lib/bytes.c
	lib/chicago.c
	lib/client.c
	lib/client_recv.c
	lib/client_send.c
	lib/messager.c
	lib/server.c
	lib/server_recv.c
	lib/server_send.c
	lib/session.c
	lib/trace.c
	lib/util.c)

ADD_LIBRARY(libcurvecpr STATIC ${libcurvecpr_headers} ${libcurvecpr_sources})
TARGET_LINK_LIBRARIES(libcurvecpr ${SODIUM_LIBRARY})



# install
INSTALL(TARGETS libcurvecpr
	LIBRARY DESTINATION lib${LIB_SUFFIX}
	ARCHIVE DESTINATION lib${LIB_SUFFIX}
	RUNTIME DESTINATION bin)
	
########################################################################
# tests
########################################################################
IF(CHECK_FOUND)
	ENABLE_TESTING()
	INCLUDE_DIRECTORIES(${LIBCURVECPR_SOURCE_DIR}/test)
	INCLUDE_DIRECTORIES(${CHECK_INCLUDE_DIR})

	# test_new_configures_object
	ADD_EXECUTABLE(test_messager_new_configures_object test/messager/test_new_configures_object.c)
	TARGET_LINK_LIBRARIES(test_messager_new_configures_object libcurvecpr ${SODIUM_LIBRARY} ${CHECK_LIBRARY})
	ADD_TEST(test_messager_new_configures_object test_messager_new_configures_object)

	# test_recv_requests_removal_from_sendmarkq
	ADD_EXECUTABLE(test_recv_requests_removal_from_sendmarkq test/messager/test_recv_requests_removal_from_sendmarkq.c)
	TARGET_LINK_LIBRARIES(test_recv_requests_removal_from_sendmarkq libcurvecpr ${SODIUM_LIBRARY} ${CHECK_LIBRARY})
	ADD_TEST(test_recv_requests_removal_from_sendmarkq test_recv_requests_removal_from_sendmarkq)

	# test_send_with_1_failure_moves_message_from_sendq
	ADD_EXECUTABLE(test_send_with_1_failure_moves_message_from_sendq test/messager/test_send_with_1_failure_moves_message_from_sendq.c)
	TARGET_LINK_LIBRARIES(test_send_with_1_failure_moves_message_from_sendq libcurvecpr ${SODIUM_LIBRARY} ${CHECK_LIBRARY})
	ADD_TEST(test_send_with_1_failure_moves_message_from_sendq test_send_with_1_failure_moves_message_from_sendq)

	# test_timeout_callback_fires
	ADD_EXECUTABLE(test_timeout_callback_fires test/messager/test_timeout_callback_fires.c)
	TARGET_LINK_LIBRARIES(test_timeout_callback_fires libcurvecpr ${SODIUM_LIBRARY} ${CHECK_LIBRARY})
	ADD_TEST(test_timeout_callback_fires test_timeout_callback_fires)

	# test_nanoseconds
	ADD_EXECUTABLE(test_nanoseconds test/util/test_nanoseconds.c)
	TARGET_LINK_LIBRARIES(test_nanoseconds libcurvecpr ${SODIUM_LIBRARY} ${CHECK_LIBRARY})
	ADD_TEST(test_nanoseconds test_nanoseconds)
ENDIF(CHECK_FOUND)