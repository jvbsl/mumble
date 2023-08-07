# Copyright 2020-2023 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.

$profiledir = $Env:USERPROFILE 

$vcpkgdir = $ENV:VCPKG_ROOT
if (-not (Test-Path $vcpkgdir)) {
    $vcpkgdir = $profiledir + "\vcpkg"
}

if ($args.Contains('--shared')) {
    $BUILD_TYPE_ADDITION="" # shared is default without anything added to the triplet
} else {
    $BUILD_TYPE_ADDITION="-static-md" # Default to static
}

$mumble_deps = "qt5-base[mysqlplugin,postgresqlplugin]",
               "qt5-svg",
               "qt5-tools",
               "qt5-translations",
               "boost-accumulators",
               "opus",
               "poco",
               "libvorbis",
               "libogg",
               "libflac",
               "libsndfile",
               "mdnsresponder",
               "protobuf",
               "zlib", 
               "zeroc-ice-mumble"

$ErrorActionPreference = 'Stop'

function vcpkg_install {
	Param(
		[string[]] $packages,

		[string] $targetTriplet,
		[switch] $cleanAfterBuild = $false
	)
	
	if ($cleanAfterBuild) {
		./vcpkg.exe install $packages --triplet $targetTriplet --clean-after-build --recurse
	} else {
		./vcpkg.exe install $packages --triplet $targetTriplet --recurse
	}
	
	if (-not $?) {
		Write-Error("Failed at installing package $package ($targetTriplet)")
	}
}

$prevDir=pwd

try {
	Write-Host "Setting triplets for $Env:PROCESSOR_ARCHITECTURE"
	if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
		$triplet = "x64-windows$BUILD_TYPE_ADDITION"
		$xcompile_triplet = "x86-windows$BUILD_TYPE_ADDITION"
	} else {
		$triplet = "x86-windows$BUILD_TYPE_ADDITION"
	}

	Write-Host "Checking for $vcpkgdir..."
	if (-not (Test-Path $vcpkgdir)) {
		git clone https://github.com/Microsoft/vcpkg.git $vcpkgdir
	}

	if (Test-Path $vcpkgdir) {
		if (-not (Test-Path $vcpkgdir/ports/zeroc-ice-mumble)) {
			Write-Host "Adding port for ZeroC Ice..."
			Copy-Item -Path $PSScriptRoot/../../helpers/vcpkg/ports/zeroc-ice-mumble -Destination $vcpkgdir/ports -Recurse
		}
		
		cd $vcpkgdir

		if (-not (Test-Path -LiteralPath $vcpkgdir/vcpkg.exe)) {
			Write-Host "Installing vcpkg..."
			./bootstrap-vcpkg.bat -disableMetrics
		}

		if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
			Write-Host "Installing cross compile packages..."
			vcpkg_install -package boost-optional -targetTriplet $xcompile_triplet -cleanAfterBuild
		}

		Write-Host "Beginning package install($mumble_deps) $triplet..."

		vcpkg_install -package $mumble_deps -targetTriplet $triplet -cleanAfterBuild
	}
} catch {
	# rethrow
	throw $_
} finally {
	# restore previous directory
	cd $prevDir
}
