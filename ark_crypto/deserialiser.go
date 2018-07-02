// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

func Deserialise(transaction string) {
	// deserialiseHeader(transaction)
	// deserialiseTypeSpecific(transaction)
	// deserialiseVersionOne(transaction)
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC DESERIALISING ///////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseHeader(transaction interface{}) {

}

func deserialiseTypeSpecific(transaction interface{}) {

}

func deserialiseVersionOne(transaction interface{}) {

}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFICDE SERIALISING /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseDelegateRegistration(bytes []byte) {

}

func deserialiseDelegateResignation(bytes []byte) {

}

func deserialiseIpfs(bytes []byte) {

}

func deserialiseMultiPayment(bytes []byte) {

}

func deserialiseMultiSignatureRegistration(bytes []byte) {

}

func deserialiseSecondSignatureRegistration(bytes []byte) {

}

func deserialiseTimelockTransfer(bytes []byte) {

}

func deserialiseTransfer(bytes []byte) {

}

func deserialiseVote(bytes []byte) {

}
