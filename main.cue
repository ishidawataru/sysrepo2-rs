package main

import (
	"dagger.io/dagger"
	"universe.dagger.io/docker"
)

dagger.#Plan & {
	client: filesystem: ".": {
		read: contents: dagger.#FS
	}

	actions: {
		build: docker.#Dockerfile & {
			source: client.filesystem.".".read.contents
		}
		test: docker.#Run & {
			input: build.output
			command: {
				name: "make"
				args: ["test"]
			}
			mounts: pwd: {
				dest:     "/data"
				contents: client.filesystem.".".read.contents
			}
			workdir: "/data"
		}
	}
}
