#!/bin/bash

# Configurable parameters
ghidraVersion="ghidra_10.5_DEV" # Modify this line to change the version of Ghidra
pluginName="Raverside"          # Modify this line to change the plugin name

# Paths and derived variables
buildDirectory="/path/to/your/plugin/workspace/dist" # Dist is the build directory
destination="/path/to/your/.ghidra/ghidraVersion/Extensions/" # Directory where the Ghidra Extensions need to be added
ghidraPath="/path/to/your/ghidra/ghidraRun" # ghidraRun is the script to launch ghidra

# Search for the most recent build file
file=$(ls -t $buildDirectory/${ghidraVersion}_*_${pluginName}.zip | head -n 1)

if [ -z "$file" ]; then
    echo "Aucun fichier de build trouvé"
    exit 1
fi

last_modified=$(stat -c %Y "$file")

while true; do
    sleep 5
    file=$(ls -t $buildDirectory/${ghidraVersion}_*_${pluginName}.zip | head -n 1)
    new_last_modified=$(stat -c %Y "$file")
    if [ "$new_last_modified" != "$last_modified" ]; then
        pid=$(ps -edf | grep "ghidra" | awk 'NR==1 {print $2}')
        if [ -n "$pid" ]; then
            kill "$pid"
            while kill -0 "$pid" 2> /dev/null; do
                sleep 1
            done
        fi
        echo "File has been modified, unzipping..."
        unzip -o "$file" -d "$destination"
        last_modified=$new_last_modified
        echo "Lancement de Ghidra"
        $ghidraPath &>/dev/null &
    fi
done

