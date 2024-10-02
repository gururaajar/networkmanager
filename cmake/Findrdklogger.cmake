#############################################################################
# If not stated otherwise in this file or this component's Licenses.txt file
# the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

find_package(PkgConfig)

find_library(RDKLOGGER_LIBRARIES NAMES rdkloggers)
find_path(RDKLOGGER_INCLUDE_DIRS NAMES rdk_debug.h)

set(RDKLOGGER_LIBRARIES ${RDKLOGGER_LIBRARIES} CACHE PATH "Path to rdkLogger library")
set(RDKLOGGER_INCLUDE_DIRS ${RDKLOGGER_INCLUDE_DIRS} )
set(RDKLOGGER_INCLUDE_DIRS ${RDKLOGGER_INCLUDE_DIRS} CACHE PATH "Path to rdkLogger include")

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(RDKLOGGER DEFAULT_MSG RDKLOGGER_INCLUDE_DIRS RDKLOGGER_LIBRARIES)

mark_as_advanced(
    RDKLOGGER_FOUND
    RDKLOGGER_INCLUDE_DIRS
    RDKLOGGER_LIBRARIES
    RDKLOGGER_LIBRARY_DIRS
    RDKLOGGER_FLAGS)
