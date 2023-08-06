#!/bin/bash

# Copyright 2020-2023 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.


# Copyright 2020 The 'mumble-releng-experimental' Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that
# can be found in the LICENSE file in the source tree or at
# <http://mumble.info/mumble-releng-experimental/LICENSE>.

# Helper function to check if a certain parameter has been passed to the script
has_option() {
    local desiredOption="$1"
    shift
    for currentOption in "$@"; do
        if [[ $currentOption == "$desiredOption" ]]; then
            return 0
        fi
    done
    return 1
}

if ! has_option '--auto' "$@"
    then
	# Make sure the command-prompt stays open if an error is encountered so that the user can read
	# the error message before the console closes.
	# If you run call this script as part of some automation, you'll want to pass --auto
	# to make sure you don't get stuck.
	trap "printf '\n\n'; read -p 'ERROR encountered... Press Enter to exit'" ERR
fi

if ! has_option '--static' "$@"
    then
    BUILD_TYPE_ADDITION="-static"
elif ! has_option '--shared' "$@"
    then
    BUILD_TYPE_ADDITION="" # shared is without anything added to the triplet
fi

# On failed command (error code) exit the whole script
set -e
# Treat using unset variables as errors
set -u
# For piped commands on command failure fail entire pipe instead of only the last command being significant
set -o pipefail

VCPKGDIR=~/vcpkg

mumble_deps=("qt5-base[mysqlplugin,postgresqlplugin]"
            "qt5-svg"
            "qt5-tools"
            "qt5-translations"
            "boost-accumulators"
            "opus"
            "poco"
            "libvorbis"
            "libogg"
            "libflac"
            "libsndfile"
            "protobuf"
            "zlib"
            "zeroc-ice-mumble")

# Determine vcpkg triplet from OS https://github.com/Microsoft/vcpkg/blob/master/docs/users/triplets.md
# Available triplets can be printed with `vcpkg help triplet`
case "$OSTYPE" in
    msys* )
        BUILD_TYPE_ADDITION="${BUILD_TYPE_ADDITION--static}" # Default to static for msys(Windows)
        if [[ "$BUILD_TYPE_ADDITION" == "-static" ]]; then
            BUILD_TYPE_ADDITION="$BUILD_TYPE_ADDITION-md" # Link dynamically to CRT
        fi
        triplet="x64-windows$BUILD_TYPE_ADDITION"
        xcompile_triplet="x86-windows$BUILD_TYPE_ADDITION"
        ;;
    linux-gnu* )
        triplet="x64-linux$BUILD_TYPE_ADDITION"
        ;;
    darwin* )
        triplet="x64-osx$BUILD_TYPE_ADDITION"
        ;;
    * ) echo "The OSTYPE is either not defined or unsupported. Aborting...";;
esac

if [ ! -d "$VCPKGDIR" ]
    then 
        git clone https://github.com/Microsoft/vcpkg.git $VCPKGDIR
fi

if [ -d "$VCPKGDIR" ]
    then
        # copy ZeroC Ice port files
        cp -R helpers/vcpkg/ports/zeroc-ice-mumble $VCPKGDIR/ports
        cd $VCPKGDIR

        if [ ! -x $VCPKGDIR/vcpkg ]
            then
                case "$OSTYPE" in
                    msys* ) ./bootstrap-vcpkg.bat -disableMetrics
                    ;;
                    * ) bash bootstrap-vcpkg.sh -disableMetrics
                    ;;
                esac
        fi

        if [ -z "$triplet" ]
            then
            echo "Triplet type is not defined! Aborting..."
        else
            if [ $OSTYPE == msys ]
                then
                    # install dns-sd provider
                    ./vcpkg install mdnsresponder icu --triplet $triplet
                    ./vcpkg install boost-optional:$xcompile_triplet --clean-after-build
            fi

            ./vcpkg install ${mumble_deps[@]} --clean-after-build
        fi
else
    echo "Failed to retrieve the 'vcpkg' repository! Aborting..."
fi
