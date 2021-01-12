# Zero Knowledge Proofs
 
 This repository is forked from [ing-bank/zkrp](https://github.com/ing-bank/zkrp).
 The experiments are under `cmd` folder for both baseline and merkle tree implimentations.
 The [go-ethereum](https://github.com/ethereum/go-ethereum) `v1.9.25` is required as a dependency.

## Running experiments

 Clone `ethereum` repository.
 ```bash
 mkdir -p $GOPATH/src/github.com/ethereum
 cd $GOPATH/src/github.com/ethereum
 git clone https://github.com/ethereum/go-ethereum.git
 cd go-ethereum
 git checkout v1.9.25
 ```

 Clone `zkrp` repository.
 ```bash
 mkdir -p $GOPATH/src/github.com/ing-bank
 cd $GOPATH/src/github.com/ing-bank
 git clone https://github.com/aungmawjj/zkrp.git
 ```

 Build `baseline` experiment.
 ```bash
 cd $GOPATH/src/github.com/ing-bank/zkrp/cmd/baseline
 go build
 ```

 Generate proof for baseline experiment.
 ```bash
 ./baseline c 128
 ```
 where `128` is the number of users, `N`.

 Verify proof for baseline experiment.
 ```bash
 ./baseline u
 ```

 Merkle tree implementation can be run with the same procedure.

## License

This repository is GNU Lesser General Public License v3.0 licensed, as found in [LICENSE file](LICENSE) and [LICENSE.LESSER file](LICENSE.LESSER).
