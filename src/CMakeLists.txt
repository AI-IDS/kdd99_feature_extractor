# Project source & header files
file(GLOB SOURCES
  "*.h"
  "*.cpp"
)

set(INCLUDES ${PCAP_INCLUDE_DIR})
set(LIBS ${PCAP_LIBRARIES})

if(UNIX)
  # gcc warning: scoped enums only available with -std=c++0x or -std=gnu++0
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=gnu++0x")
endif()

# ntohs() function in Windows
if( WIN32 )
  set( LIBS ${LIBS} "Ws2_32")
endif()

include_directories(${INCLUDES})
add_executable(kdd99extractor ${SOURCES})
target_link_libraries(kdd99extractor ${LIBS})
