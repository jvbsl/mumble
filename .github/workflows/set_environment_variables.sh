#!/usr/bin/env bash

set -e
set -x

os=$1
build_type=$2
arch=$3
workspace=$4


if [[ "$os" == "" || "$build_type" == "" || "$arch" == "" || "$workspace" == "" ]]; then
	echo "Invalid parameters"
	exit 1
fi

# Turn variables into lowercase
os=$(echo $os | tr '[:upper:]' '[:lower:]')
# only consider name up to the hyphen
os=$(echo "$os" | sed 's/-.*//')
build_type=$(echo $build_type | tr '[:upper:]' '[:lower:]')
arch=$(echo $arch | tr '[:upper:]' '[:lower:]')


ADDITIONAL_CMAKE_OPTIONS=""
VCPKG_CMAKE_OPTIONS=""



case "$os" in
	"ubuntu")
		;;
	"windows")
		VCPKG_CMAKE_OPTIONS="-DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl"
		;;
	"macos")
		;;
	*)
		echo "OS $os is not supported"
		exit 1
		;;
esac


VCPKG_TARGET_TRIPLET=""
VCPKG_ROOT="$HOME/vcpkg"
case "$os" in
	"ubuntu")
		echo "QT_QPA_PLATFORM=offscreen" >> "$GITHUB_ENV"
		VCPKG_TARGET_TRIPLET="linux"
		VCPKG_ROOT="$GITHUB_WORKSPACE/vcpkg"
		;;
	"windows")
		VCPKG_TARGET_TRIPLET="windows"
		ADDITIONAL_CMAKE_OPTIONS="$ADDITIONAL_CMAKE_OPTIONS -Dpackaging=ON"
		VCPKG_ROOT="C:/vcpkg"
		;;
	"macos")
		VCPKG_TARGET_TRIPLET="osx"
		;;
esac

if [[ "$arch" == "64bit" ]]; then
	VCPKG_TARGET_TRIPLET="x64-$VCPKG_TARGET_TRIPLET"
else
	VCPKG_TARGET_TRIPLET="x32-$VCPKG_TARGET_TRIPLET"
fi

if [[ "$build_type" == "static" ]]; then
	ADDITIONAL_CMAKE_OPTIONS="$ADDITIONAL_CMAKE_OPTIONS -Dstatic=ON"
	if [[ "$os" == "windows" ]]; then
		VCPKG_TARGET_TRIPLET="$VCPKG_TARGET_TRIPLET-static-md"
		ADDITIONAL_CMAKE_OPTIONS="$ADDITIONAL_CMAKE_OPTIONS -Dpackaging=ON"
	fi
else
	if [[ "$os" != "windows" ]]; then
		VCPKG_TARGET_TRIPLET="$VCPKG_TARGET_TRIPLET-dynamic"
	fi
fi

if [[ "$os" != "ubuntu" || "$build_type" == "static" ]]; then
	VCPKG_CMAKE_OPTIONS="$VCPKG_CMAKE_OPTIONS -DCMAKE_TOOLCHAIN_FILE='$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake' -DVCPKG_TARGET_TRIPLET='$VCPKG_TARGET_TRIPLET' -DIce_HOME='$VCPKG_ROOT/installed/$VCPKG_TARGET_TRIPLET'"
fi



# set environment variables in a way that GitHub Actions understands and preserves
echo "ADDITIONAL_CMAKE_OPTIONS=$ADDITIONAL_CMAKE_OPTIONS" >> "$GITHUB_ENV"
echo "VCPKG_CMAKE_OPTIONS=$VCPKG_CMAKE_OPTIONS" >> "$GITHUB_ENV"
echo "VCPKG_ROOT=$VCPKG_ROOT" >> "$GITHUB_ENV"
