# Copyright 2021-2023 The Mumble Developers. All rights reserved.
# Use of this source code is governed by a BSD-style license
# that can be found in the LICENSE file at the root of the
# Mumble source tree or at <https://www.mumble.info/LICENSE>.
#
# Ensures we have downloaded and extracted a build environment into our AppVeyor
# VM before we attempt to build. If the environment archive is already present,
# this script will just extract it.
#

$PSScriptRoot/install_windows_static_64bit.ps1