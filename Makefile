build:
	bazel build deb/sandbox:all
	sudo dpkg -i bazel-bin/deb/sandbox/omogenexec_1.1.0_amd64.deb