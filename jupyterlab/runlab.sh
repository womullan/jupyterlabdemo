#!/bin/sh
#export DEBUG=1
if [ -n "${DEBUG}" ]; then
    set -x
fi
if [ -n "${GITHUB_EMAIL}" ]; then
    git config --global user.email "${GITHUB_EMAIL}"
fi
if [ -n "${GITHUB_NAME}" ]; then
    git config --global user.name "${GITHUB_NAME}"
fi
sync
cd ${HOME}
#cmd="python3 /usr/bin/jupyter-labhub \
cmd="python3 /usr/bin/jupyter-singlelabuser \
     --ip='*' --port=8888 --debug \
     --hub-api-url=${JPY_HUB_API_URL} \
     --notebook-dir=${HOME}/notebooks"
echo ${cmd}
if [ -n "${DEBUG}" ]; then
    while : ; do
        d=$(date)
        echo "${d}: sleeping."
        sleep 60
    done
else    
    exec ${cmd}
fi
