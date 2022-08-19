#!/bin/bash

function print_usage() {
	RED='\033[0;31m'
	BLUE='\033[0;34m'
	BOLD='\033[1m'
	NONE='\033[0m'

	echo -e "\n${RED}Usage${NONE}:
	.${BOLD}/docker_cmd.sh${NONE} [OPTION]"

	echo -e "\n${RED}OPTIONS${NONE}:
	${BLUE}build${NONE}: build penglai-demo image
	${BLUE}run-qemu${NONE}: run penglai-demo image in (modified) qemu
	"
}

# no arguments
if [ $# == 0 ]; then
	echo "Default: building penglai demo image"
	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.1 bash scripts/build_opensbi.sh
	exit 0
fi

if [[ $1 == *"help"* ]]; then
	print_usage
	exit 0
fi

# build penglai
if [[ $1 == *"build"* ]]; then
	echo "Build: building penglai demo image"
	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.1 bash scripts/build_opensbi.sh
	exit 0
fi

# build penglai
if [[ $1 == *"qemu"* ]]; then
	echo "Run: run penglai demo image in Qemu (built with openEuler)"
	./run_openeuler.sh
	exit 0
fi

# run docker
if [[ $1 == *"docker"* ]]; then
	echo "Run: run docker"
	#sudo docker run --privileged --cap-add=ALL  -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.1
	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --network=host --rm -it ddnirvana/penglai-enclave:v0.5 bash
	exit 0
fi

# make clean
if [[ $1 == *"clean"* ]]; then
	echo "Clean: make clean"
	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.1 make clean
	exit 0
fi


print_usage
exit 1
