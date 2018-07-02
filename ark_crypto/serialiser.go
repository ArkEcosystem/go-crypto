// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

func Serialise(transaction interface{}) {
	// serialiseHeader(transaction)
	// serialiseVendorField(transaction)
	// serialiseTypeSpecific(transaction)
	// serialiseSignatures(transaction)
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC SERIALISING /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func serialiseHeader(bytes []byte) {

}

func serialiseVendorField(bytes []byte) {

}

func serialiseTypeSpecific(bytes []byte) {

}

func serialiseSignatures(bytes []byte) {

}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFIC SERIALISING ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func serialiseDelegateRegistration(bytes []byte) {

}

func serialiseDelegateResignation(bytes []byte) {

}

func serialiseIpfs(bytes []byte) {

}

func serialiseMultiPayment(bytes []byte) {

}

func serialiseMultiSignatureRegistration(bytes []byte) {

}

func serialiseSecondSignatureRegistration(bytes []byte) {

}

func serialiseTimelockTransfer(bytes []byte) {

}

func serialiseTransfer(bytes []byte) {

}

func serialiseVote(bytes []byte) {

}
