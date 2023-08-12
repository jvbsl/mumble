# Copyright 2022-2023 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

vcpkg_from_github(
	OUT_SOURCE_PATH SOURCE_PATH
	REPO jvbsl/ice
	REF 3.7
	SHA512 614b6a0041a5c0570a4056e1fa213e9f536534875c72c0f736d75d4ce53a84e68112009496bf4c1b8fddc98100ded15d1857a79b1e77bcd61ac947eacecb673d
)

if("cpp11" IN_LIST FEATURES)
	vcpkg_configure_cmake(
		SOURCE_PATH ${SOURCE_PATH}
		PREFER_NINJA
		OPTIONS
			-DBUILD_ICE_CXX=ON
			-DBUILD_ICE_CPP11=ON
	)
else()
	vcpkg_configure_cmake(
		SOURCE_PATH ${SOURCE_PATH}
		PREFER_NINJA
		OPTIONS
			-DBUILD_ICE_CXX=ON
	)
endif()

vcpkg_install_cmake()

vcpkg_copy_pdbs()

file(INSTALL ${SOURCE_PATH}/cpp/include DESTINATION ${CURRENT_PACKAGES_DIR})
file(INSTALL ${SOURCE_PATH}/slice DESTINATION ${CURRENT_PACKAGES_DIR})
file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/include 
	DESTINATION ${CURRENT_PACKAGES_DIR}
)

if(EXISTS ${CURRENT_PACKAGES_DIR}/bin)
    file(INSTALL ${CURRENT_PACKAGES_DIR}/bin/ DESTINATION ${CURRENT_PACKAGES_DIR}/tools/Ice)
endif()

file(INSTALL ${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/icebuilder/bin/ DESTINATION ${CURRENT_PACKAGES_DIR}/tools/Ice)

vcpkg_copy_tool_dependencies(${CURRENT_PACKAGES_DIR}/tools/Ice)

if(UNIX)
    vcpkg_execute_required_process(COMMAND chmod -R +x Ice
        WORKING_DIRECTORY ${CURRENT_PACKAGES_DIR}/tools
        LOGNAME ice-${TARGET_TRIPLET}-setexe
    )
endif()

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/bin ${CURRENT_PACKAGES_DIR}/debug/bin)

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)
  
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)
file(INSTALL ${SOURCE_PATH}/ICE_LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT})
