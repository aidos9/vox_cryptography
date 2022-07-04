import json

dict = json.load(open("test_cases.json", "r"))

# Create blowfish tests
with open("tests/raw_blowfish.rs", "w") as raw_blowfish_file:
    i = 1
    raw_blowfish_file.write(
        "use vox_cryptography::block_ciphers::blowfish::{Blowfish, BlowfishKey};\nuse vox_cryptography::block_ciphers::BlockCipher;\nuse pretty_assertions::assert_eq;\n\n")

    for case in dict["raw"]["blowfish"]:
        header_encrypt = "#[test]\nfn raw_blowfish_encrypt_test_{}() {{\n".format(
            i)
        header_decrypt = "#[test]\nfn raw_blowfish_decrypt_test_{}() {{\n".format(
            i)

        key = case[0]
        clear = case[1]
        cipher = case[2]

        key = "\tlet key = hex::decode(\"{}\").unwrap();\n".format(key)
        input_encrypt = "\tlet mut input = [0u8; 8];\n\thex::decode_to_slice(\"{}\", &mut input).unwrap();\n\n".format(
            clear)
        input_decrypt = "\tlet mut input = [0u8; 8];\n\thex::decode_to_slice(\"{}\", &mut input).unwrap();\n\n".format(
            cipher)
        cipher_line = "\tlet cipher = Blowfish::new(BlowfishKey::new(&key).unwrap(), input);\n"
        assert_statement_encrypt = "\tassert_eq!(hex::encode(cipher.encrypt()), \"{}\");\n}}\n\n".format(
            cipher)
        assert_statement_decrypt = "\tassert_eq!(hex::encode(cipher.decrypt()), \"{}\");\n}}\n\n".format(
            clear)

        raw_blowfish_file.write(header_encrypt)
        raw_blowfish_file.write(key)
        raw_blowfish_file.write(input_encrypt)
        raw_blowfish_file.write(cipher_line)
        raw_blowfish_file.write(assert_statement_encrypt)

        raw_blowfish_file.write(header_decrypt)
        raw_blowfish_file.write(key)
        raw_blowfish_file.write(input_decrypt)
        raw_blowfish_file.write(cipher_line)
        raw_blowfish_file.write(assert_statement_decrypt)

        i += 1
