# Project source & header files
file(GLOB SOURCES
  "*.h"
  "*.cpp"
)

set(INCLUDES ${PCAP_INCLUDE_DIR})
set(LIBS ${PCAP_LIBRARIES})

# ntohs() function in Windows
if( WIN32 )
  set( LIBS ${LIBS} "Ws2_32")
endif()

include_directories(${INCLUDES})
add_executable(kdd99extractor ${SOURCES})
target_link_libraries(kdd99extractor ${LIBS})
