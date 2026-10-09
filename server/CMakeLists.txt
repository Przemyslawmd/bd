

set(DISABLE_DBUS ON CACHE BOOL "" FORCE)
set(DISABLE_RDMA ON CACHE BOOL "" FORCE)
set(ENABLE_REMOTE OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

include(FetchContent)

FetchContent_Declare(
	libpcap
	GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap
	GIT_TAG libpcap-1.11.0
)

FetchContent_MakeAvailable(libpcap)


add_executable(
	bd
	main.cpp
)

target_include_directories(
		bd
		PRIVATE
		build/_deps/libpcap-src
)

target_link_libraries(bd PRIVATE pcap_static)

