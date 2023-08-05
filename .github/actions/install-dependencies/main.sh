#!/usr/bin/env bash

os="$1"
dep_type="$2"
arch="$3"

if [[ "$os" == "" || "$dep_type" == "" || "$arch" == "" ]]; then
	echo "Invalid/Missing parameters"
	exit 1
fi

# Turn variables into lowercase
os=$(echo $os | tr '[:upper:]' '[:lower:]')
# only consider name up to the hyphen
os=$(sed 's/-.*//' <<< "$os")
dep_type=$(echo $dep_type | tr '[:upper:]' '[:lower:]')
arch=$(echo $arch | tr '[:upper:]' '[:lower:]')

echo "Installing dependencies for $os ($dep_type) - $arch"

if [[ "$os" == "windows" ]]; then
    ADDITIONALPATH="$USERPROFILE\.dotnet\tools"
else
    ADDITIONALPATH="$HOME/.dotnet/tools"
fi

script_dir=$(dirname "$0")
script_name="install_${os}_${dep_type}_${arch}.sh"

if [ ! -f "$script_dir/$script_name" ]; then
    script_name="install_${os}_${dep_type}_${arch}.ps1"

    pwsh "$script_dir/$script_name"
else
    "$script_dir/$script_name"
fi

# Execute respective script