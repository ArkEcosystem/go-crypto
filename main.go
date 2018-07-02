package main

import (
    "./ark_crypto"
    "github.com/davecgh/go-spew/spew"
)

func main() {
    spew.Dump(crypto.MAINNET)
    spew.Dump(crypto.DEVNET)
    spew.Dump(crypto.TESTNET)

    spew.Dump("Hello World!")
}
