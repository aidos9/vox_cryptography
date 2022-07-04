use vox_cryptography::block_ciphers::blowfish::{Blowfish, BlowfishKey};
use pretty_assertions::assert_eq;

#[test]
fn raw_blowfish_encrypt_test_1() {
	let key = hex::decode("0000000000000000").unwrap();
	let input = hex::decode("0000000000000000").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "4ef997456198dd78");
}

#[test]
fn raw_blowfish_encrypt_test_2() {
	let key = hex::decode("ffffffffffffffff").unwrap();
	let input = hex::decode("ffffffffffffffff").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "51866fd5b85ecb8a");
}

#[test]
fn raw_blowfish_encrypt_test_3() {
	let key = hex::decode("3000000000000000").unwrap();
	let input = hex::decode("1000000000000001").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "7d856f9a613063f2");
}

#[test]
fn raw_blowfish_encrypt_test_4() {
	let key = hex::decode("1111111111111111").unwrap();
	let input = hex::decode("1111111111111111").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "2466dd878b963c9d");
}

#[test]
fn raw_blowfish_encrypt_test_5() {
	let key = hex::decode("0123456789abcdef").unwrap();
	let input = hex::decode("1111111111111111").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "61f9c3802281b096");
}

#[test]
fn raw_blowfish_encrypt_test_6() {
	let key = hex::decode("1111111111111111").unwrap();
	let input = hex::decode("0123456789abcdef").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "7d0cc630afda1ec7");
}

#[test]
fn raw_blowfish_encrypt_test_7() {
	let key = hex::decode("0000000000000000").unwrap();
	let input = hex::decode("0000000000000000").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "4ef997456198dd78");
}

#[test]
fn raw_blowfish_encrypt_test_8() {
	let key = hex::decode("fedcba9876543210").unwrap();
	let input = hex::decode("0123456789abcdef").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "0aceab0fc6a0a28d");
}

#[test]
fn raw_blowfish_encrypt_test_9() {
	let key = hex::decode("7ca110454a1a6e57").unwrap();
	let input = hex::decode("01a1d6d039776742").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "59c68245eb05282b");
}

#[test]
fn raw_blowfish_encrypt_test_10() {
	let key = hex::decode("0131d9619dc1376e").unwrap();
	let input = hex::decode("5cd54ca83def57da").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "b1b8cc0b250f09a0");
}

#[test]
fn raw_blowfish_encrypt_test_11() {
	let key = hex::decode("07a1133e4a0b2686").unwrap();
	let input = hex::decode("0248d43806f67172").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "1730e5778bea1da4");
}

#[test]
fn raw_blowfish_encrypt_test_12() {
	let key = hex::decode("3849674c2602319e").unwrap();
	let input = hex::decode("51454b582ddf440a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "a25e7856cf2651eb");
}

#[test]
fn raw_blowfish_encrypt_test_13() {
	let key = hex::decode("04b915ba43feb5b6").unwrap();
	let input = hex::decode("42fd443059577fa2").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "353882b109ce8f1a");
}

#[test]
fn raw_blowfish_encrypt_test_14() {
	let key = hex::decode("0113b970fd34f2ce").unwrap();
	let input = hex::decode("059b5e0851cf143a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "48f4d0884c379918");
}

#[test]
fn raw_blowfish_encrypt_test_15() {
	let key = hex::decode("0170f175468fb5e6").unwrap();
	let input = hex::decode("0756d8e0774761d2").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "432193b78951fc98");
}

#[test]
fn raw_blowfish_encrypt_test_16() {
	let key = hex::decode("43297fad38e373fe").unwrap();
	let input = hex::decode("762514b829bf486a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "13f04154d69d1ae5");
}

#[test]
fn raw_blowfish_encrypt_test_17() {
	let key = hex::decode("07a7137045da2a16").unwrap();
	let input = hex::decode("3bdd119049372802").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "2eedda93ffd39c79");
}

#[test]
fn raw_blowfish_encrypt_test_18() {
	let key = hex::decode("04689104c2fd3b2f").unwrap();
	let input = hex::decode("26955f6835af609a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "d887e0393c2da6e3");
}

#[test]
fn raw_blowfish_encrypt_test_19() {
	let key = hex::decode("37d06bb516cb7546").unwrap();
	let input = hex::decode("164d5e404f275232").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "5f99d04f5b163969");
}

#[test]
fn raw_blowfish_encrypt_test_20() {
	let key = hex::decode("1f08260d1ac2465e").unwrap();
	let input = hex::decode("6b056e18759f5cca").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "4a057a3b24d3977b");
}

#[test]
fn raw_blowfish_encrypt_test_21() {
	let key = hex::decode("584023641aba6176").unwrap();
	let input = hex::decode("004bd6ef09176062").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "452031c1e4fada8e");
}

#[test]
fn raw_blowfish_encrypt_test_22() {
	let key = hex::decode("025816164629b007").unwrap();
	let input = hex::decode("480d39006ee762f2").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "7555ae39f59b87bd");
}

#[test]
fn raw_blowfish_encrypt_test_23() {
	let key = hex::decode("49793ebc79b3258f").unwrap();
	let input = hex::decode("437540c8698f3cfa").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "53c55f9cb49fc019");
}

#[test]
fn raw_blowfish_encrypt_test_24() {
	let key = hex::decode("4fb05e1515ab73a7").unwrap();
	let input = hex::decode("072d43a077075292").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "7a8e7bfa937e89a3");
}

#[test]
fn raw_blowfish_encrypt_test_25() {
	let key = hex::decode("49e95d6d4ca229bf").unwrap();
	let input = hex::decode("02fe55778117f12a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "cf9c5d7a4986adb5");
}

#[test]
fn raw_blowfish_encrypt_test_26() {
	let key = hex::decode("018310dc409b26d6").unwrap();
	let input = hex::decode("1d9d5c5018f728c2").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "d1abb290658bc778");
}

#[test]
fn raw_blowfish_encrypt_test_27() {
	let key = hex::decode("1c587f1c13924fef").unwrap();
	let input = hex::decode("305532286d6f295a").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "55cb3774d13ef201");
}

#[test]
fn raw_blowfish_encrypt_test_28() {
	let key = hex::decode("0101010101010101").unwrap();
	let input = hex::decode("0123456789abcdef").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "fa34ec4847b268b2");
}

#[test]
fn raw_blowfish_encrypt_test_29() {
	let key = hex::decode("1f1f1f1f0e0e0e0e").unwrap();
	let input = hex::decode("0123456789abcdef").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "a790795108ea3cae");
}

#[test]
fn raw_blowfish_encrypt_test_30() {
	let key = hex::decode("e0fee0fef1fef1fe").unwrap();
	let input = hex::decode("0123456789abcdef").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "c39e072d9fac631d");
}

#[test]
fn raw_blowfish_encrypt_test_31() {
	let key = hex::decode("0000000000000000").unwrap();
	let input = hex::decode("ffffffffffffffff").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "014933e0cdaff6e4");
}

#[test]
fn raw_blowfish_encrypt_test_32() {
	let key = hex::decode("ffffffffffffffff").unwrap();
	let input = hex::decode("0000000000000000").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "f21e9a77b71c49bc");
}

#[test]
fn raw_blowfish_encrypt_test_33() {
	let key = hex::decode("0123456789abcdef").unwrap();
	let input = hex::decode("0000000000000000").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "245946885754369a");
}

#[test]
fn raw_blowfish_encrypt_test_34() {
	let key = hex::decode("fedcba9876543210").unwrap();
	let input = hex::decode("ffffffffffffffff").unwrap();

	let cipher = Blowfish::new(BlowfishKey::new(&key).unwrap());
	assert_eq!(hex::encode(cipher.encrypt(&input).unwrap()), "6b5c5a9c5d9e0a5a");
}

