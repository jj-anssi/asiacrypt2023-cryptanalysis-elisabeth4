# Supporting code for the ASIACRYPT 2023 paper "Cryptanalysis of Elisabeth-4"

This repository contains source code implementing the attack described in the ASIACRYPT 2023 paper entitled "Cryptanalysis of Elisabeth-4", on a toy cipher to reduce the time and memory complexities. Please refer to the paper for more details.

We provide two ways to run the code:
1. A Docker environment which simplifies the installation of required dependencies: you simply need a working Docker environnement to get a shell in the current directory with all the dependencies already installed.
2. A small tutorial to install the three main dependencies by hand.

### Docker usage

To use the provided `Dockerfile`, simply run the following commands

```sh
$ make docker-build # build the Docker image
$ make docker-run   # execute a shell in the Docker image
# The following command is executed in the Docker container
cryptanalysis@asiacrypt2023:/app$ make test
```

### Install dependencies by hand

To compile the code from this repository, you will need the following dependencies:

* `libm4ri`
* `libgsl` 
* `Cado-NFS`
* `OpenMP`

We provide detailed informations to install them of your system, assuming your distribution supports `apt`.

#### `libm4ri`

```sh
$ apt install libm4ri-dev
```

#### `OpenMP`

```sh
$ apt install libomp-dev
```

#### `libgsl` (version 2.7)

```sh
$ wget https://gnu.mirror.net.in/gnu/gsl/gsl-2.7.1.tar.gz
$ tar xzvf gsl-2.7.1.tar.gz
$ cd gsl-2.7.1
$ ./configure --prefix=<dir>
$ make
$ sudo make install
```

**Note:** Adjust the `gsl-2.7.1` installation directory in the `Makefile` (in both`CFLAGS` and `LFLAGS`). If necessary, make local install of gsl libraries available.

```sh
$ export LD_LIBRARY_PATH=<dir>/lib
```

#### `Cado-NFS`

```sh
$ git clone https://gitlab.inria.fr/cado-nfs/cado-nfs.git
```

Compile it with `make`.

We are going to make use of binaries and scripts located in `build/<hostname>/linalg/bwc`

```sh
$ export PATH=<cado-dir>/build/<hostname>/linalg/bwc/$PATH
```

### Compilation

After installing the dependencies, compile the code in this repository by running

```sh
make
```

### Running the attack on Elisabeth-4 with no filtering

After a successful compilation, run the attack as follows.
We also provide the `make test` command in the `Makefile` that runs the commands explicited below.

Select the active variant in the source code (`main.c`, variable `activeVariant` line 68):
```c
variant *activeVariant = &lily3_12_2;
```

Generate the polynomial Basis associated to the variant
```sh
$ mkdir lily3_12_2
$ ./elisabeth buildPolynomialBasisMatrix lily3_12_2
```

Generate the basis matrices
```sh
$ ./elisabeth buildBasisMatrices lily3_12_2
```

The previous two steps are done once for all for a given variant.

Generate an instance of the system to solve
```sh
$ mkdir lily3_12_2/instance1
$ ./elisabeth buildInstance lily3_12_2 lily3_12_2/instance1
```

Resolution of the system, using `Cado-NFS`
```sh
$ cd lily3_12_2/instance1
```

Generate weight files
```sh
$ mf_scan2 tA.bin
```

Generate balancing data.
To adapt the number of threads to your machine change `2x2` to `nxn` with `n**2` smaller that the number of cores available of your machine.

```sh
$ mf_bal                \
    2x2                 \
    mfile=tA.bin        \
    reorder=columns     \
    rwfile=tA.rw.bin    \
    cwfile=tA.cw.bin
```

Perform Block Wiedemann, with:
* `mn`: should be set to 64 on 64-bit processors.
* `thr`: reuse the input to `mf_bal`.
* `balancing`: use the binary file that was created by `mf_bal`.
* Adapt the absolute path to the files.

```sh
$ mkdir /tmp/wdir
$ bwc.pl :complete                          \
  wdir=/tmp/wdir                            \
  mn=64                                     \
  nullspace=left                            \
  matrix=/app/lily3_12_2/instance1/tA.bin   \
  thr=2x2                                   \
  balancing=/app/lily3_12_2/instance1/tA.2x2.*.bin
```

Get the solution from the working directory
```sh
$ cp /tmp/wdir/W .
$ cd ../..
```

```sh
Print solution
$ ./elisabeth printSolution lily3_12_2/instance1
```

### Running the attack on Elisabeth-4 with filtering

We also provide the command `make test-filtering` that runs an optimized attack as described in the paper that relies on the filtering technique.

You can have a look at the file `run-test-with-filtering.sh` to get more details about the various steps.

### Authors

* Rachelle HEIM BOISSIER
* Henri GILBERT
* Jérémy JEAN
* Jean-René REINHARD
