#[cfg(test)]
mod tests {
    extern crate base64;
    extern crate hex;
    extern crate openssl;
    extern crate rand;
    extern crate log;
    extern crate pretty_env_logger;

    use self::rand::Rng;
    use log::{info, error};
    use hashbrown::{HashMap};
    use itertools::Itertools;
    use openssl::symm::{Cipher, Crypter, Mode};
    use std::borrow::Borrow;
    use std::cmp::Ordering;
    use std::error::Error;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use std::path::Path;

    #[test]
    fn test_set1_challenge_1() {
        let input_string = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let output_string =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

        let b64_result = match hex::decode(input_string) {
            Ok(input) => base64::encode(input.as_slice()),
            Err(e) => panic!("Could not parse Base64 string: {}", e.description()),
        };

        assert_eq!(output_string, b64_result);
    }

    #[test]
    fn test_set1_challenge_2() {
        let a = hex::decode(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
        let b = hex::decode(String::from("686974207468652062756c6c277320657965")).unwrap();
        let t = hex::decode(String::from("746865206b696420646f6e277420706c6179")).unwrap();

        assert_eq!(t, fixed_xor(&a, &b));
    }

    #[test]
    fn test_set1_challenge_3() {
        let target = hex::decode(String::from(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ))
        .expect("Could not Hex decode message");

        assert_eq!(
            String::from_utf8(get_max_xor_score(target).plaintext).unwrap_or_default(),
            "Cooking MC's like a pound of bacon"
        );
    }

    #[test]
    fn test_set1_challenge_4() {
        let path = Path::new("/Users/mclean/Downloads/4.txt");
        let bufread_lines = get_buffered_lines(path);
        let mut file_scores = Vec::new();
        for line in bufread_lines.lines() {
            match line {
                Ok(line) => {
                    let target =
                        hex::decode(line).expect("Could not perform hex decode of target string.");
                    match get_max_xor_score(target) {
                        s => file_scores.push(s),
                    }
                }
                Err(e) => error!("Error reading line from file {}", e.description()),
            }
        }

        match get_max_score_result(&mut file_scores) {
            m => assert_eq!(
                String::from_utf8(m.plaintext).unwrap_or_default(),
                String::from("Now that the party is jumping\n")
            ),
        }
    }

    #[test]
    fn test_set1_challenge_5() {
        let target = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .as_bytes()
            .to_vec();
        let key = "ICE".as_bytes();
        let mut res = Vec::new();
        for b in target.iter().as_slice().chunks(3) {
            for (i, elem) in b.iter().enumerate() {
                res.push(key[i] ^ elem.clone());
            }
        }

        let res_hex = hex::encode(res);

        assert_eq!(res_hex.as_str(), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn test_set1_challenge_6() {
        pretty_env_logger::init();
        let lhs_string = "this is a test";
        let rhs_string = "wokka wokka!!!";
        let test_score = compute_hamming_distance(lhs_string.as_bytes(), rhs_string.as_bytes());

        assert_eq!(test_score, 37);

        let path = Path::new("/Users/mclean/Downloads/6.txt");
        let mut input = match File::open(&path) {
            Ok(file) => file,
            Err(why) => panic!("Could not open {}:{}", path.display(), why.description()),
        };

        let mut s = String::new();
        match input.read_to_string(&mut s) {
            Err(why) => panic!("Could not read {}:{}", path.display(), why.description()),
            Ok(_) => info!("Read contents of {}", path.display()),
        }

        let b64_result = match base64::decode(s.replace('\n', "").as_bytes()) {
            Err(_why) => panic!("Could not decode string into base64"),
            Ok(res) => res,
        };

        let mut norm_keysizes: Vec<(u64, f32)> = Vec::new();
        for ks in 2..41 {
            let mut ks_average: f32 = 0.0;
            for chunk_pair in b64_result.chunks(ks as usize).take(4).combinations(2) {
                ks_average += (compute_hamming_distance(chunk_pair[0], chunk_pair[1]) / ks) as f32;
            }
            norm_keysizes.push((ks, ks_average / 4.0));
        }

        norm_keysizes.sort_by(|a, b| a.1.partial_cmp(b.1.borrow()).unwrap_or(Ordering::Equal));
        info!(
            "Shortest distance found with key size {} : {}",
            norm_keysizes[0].1, norm_keysizes[0].0
        );

        // Iterate through and transpose the blocks
        let keysize = norm_keysizes[0].0 as usize;
        let blocks_vec: Vec<_> = b64_result
            .chunks(keysize)
            .map(|key_sized_chunk| key_sized_chunk.to_vec())
            .collect();

        // Initialize plaintext chunk vector.
        let mut plaintext_chunks: Vec<Vec<u8>> = Vec::new();
        for _v in 0..keysize {
            plaintext_chunks.push(Vec::new());
        }

        // Perform transposition into a vector of vectors.
        for j in 0..keysize {
            for c in blocks_vec.iter() {
                match c.get(j) {
                    Some(ch) => plaintext_chunks[j].push(ch.clone()),
                    None => (),
                }
            }
        }

        // Score each chunk to find the most likely key byte per chunk
        let mut key = Vec::new();
        for chunk in plaintext_chunks.iter() {
            match get_max_xor_score(chunk.clone()) {
                t => key.push(t.key),
            }
        }

        let key_string = String::from_utf8(key.clone());

        let mut clear_text_vec = Vec::new();
        for (i, elem) in b64_result.iter().enumerate() {
            clear_text_vec.push(elem ^ key[i % keysize]);
        }

        let clear_text =
            String::from_utf8(clear_text_vec).expect("Could not convert final cleartext result");
        info!("Final Cleartext =>\n{}", clear_text);

        assert_eq!(
            key_string.expect("key value is missing for comparison"),
            "Terminator X: Bring the noise"
        );
    }

    #[test]
    fn test_set1_challenge_7() {
        pretty_env_logger::init();
        let key = "YELLOW SUBMARINE";

        let raw_file_contents = read_file_to_string("/Users/mclean/Downloads/7.txt");

        let b64_decode = b64decode_to_vec(raw_file_contents);

        let output_cleartext = aes_ecb_128(&key.as_bytes().to_vec(), &b64_decode, false);
        let test_string = String::from("Hello my name i");
        let _output_test = aes_ecb_128(&key.as_bytes().to_vec(), &test_string.into_bytes(), true);

        assert_eq!(output_cleartext.len(), 2876);
    }

    #[test]
    fn test_set1_challenge_8() {
        pretty_env_logger::init();
        let bufread_lines = get_buffered_lines(Path::new("/Users/mclean/Downloads/8.txt"));
        let mut target_line_no = 0;

        for (line_no, line) in bufread_lines.lines().enumerate() {
            match line {
                Ok(l) => {
                    let decode_str = hex::decode(l).expect("Cannot decode hex string");
                    if is_ecb_mode(&decode_str) {
                        target_line_no = line_no + 1;
                    }
                }
                Err(_e) => error!("Error reading line from file no. {}", line_no),
            }
        }
        assert_eq!(target_line_no, 133);
    }

    #[test]
    fn test_set2_challenge_9() {
        let input = String::from("YELLOW SUBMARINE");
        let target = String::from("YELLOW SUBMARINE\x04\x04\x04\x04");
        let result = pad_bytes(input.into_bytes(), 20);

        assert_eq!(String::from_utf8(result).unwrap_or_default(), target);
    }

    #[test]
    fn test_set2_challenge_10() {
        pretty_env_logger::init();
        let plaintext_test = "Hello my name is Alistair.";
        let key = "YELLOW SUBMARINE";

        // Sanity check CBC mode on test data
        let iv: Vec<u8> = vec![0u8; 16];
        let cipher_text = aes_cbc_128_enc(
            &key.as_bytes().to_vec(),
            &plaintext_test.as_bytes().to_vec(),
            &iv,
        );
        let test_result = aes_cbc_128_dec(&key.as_bytes().to_vec(), &cipher_text, &iv);
        assert_eq!(test_result, plaintext_test.as_bytes());

        // Ok lets read in the file now and decrypt it
        let p = Path::new("/Users/mclean/Downloads/10.txt");
        let mut fh = File::open(p).expect("Could not open file.");
        let mut contents = String::new();
        fh.read_to_string(&mut contents)
            .expect("Could not read from file.");

        let input_bytes = base64::decode(contents.replace('\n', "").as_bytes())
            .expect("Could not base64 decode file.");
        let final_result = aes_cbc_128_dec(&key.as_bytes().to_vec(), &input_bytes, &iv);
        let result_string =
            String::from_utf8(final_result).expect("Could not parse UTF-8 String from input");
        info!("{}", result_string);
        assert_eq!(
            result_string[0..33],
            String::from("I'm back and I'm ringin' the bell")
        );
    }

    #[test]
    fn test_set2_challenge_11() {
        let mut encoded_ecb = 0;
        let mut encoded_cbc = 0;
        let some_random_input =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .as_bytes().to_vec();

        for _i in 0..10000 {
            let result = encryption_oracle(&some_random_input);
            if is_ecb_mode(&result) {
                encoded_ecb += 1;
            } else {
                encoded_cbc += 1;
            }
        }

        let crypt_ratio = encoded_cbc as f32 / encoded_ecb as f32;
        info!("Crypt Ratio = {}", crypt_ratio);
        assert_eq!((crypt_ratio < 1.2), true);
    }

    fn encryption_oracle(plaintext: &Vec<u8>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let random_bytes_upfront = create_random_bytes(rng.gen_range(5, 11));
        let random_bytes_backend = create_random_bytes(rng.gen_range(5, 11));
        let random_aes_key = generate_random_aes_key();
        let mut expanded_plaintext = Vec::with_capacity(
            plaintext.len() + random_bytes_upfront.len() + random_bytes_backend.len(),
        );
        expanded_plaintext.extend(random_bytes_upfront.iter());
        expanded_plaintext.extend(plaintext.iter());
        expanded_plaintext.extend(random_bytes_backend.iter());

        let decider = rng.gen_bool(0.5);
        if decider {
            aes_ecb_128(&random_aes_key, &expanded_plaintext, true)
        } else {
            aes_cbc_128_enc(
                &random_aes_key,
                &expanded_plaintext,
                &create_random_bytes(16),
            )
        }
    }

    fn generate_random_aes_key() -> Vec<u8> {
        create_random_bytes(16)
    }

    fn create_random_bytes(no_of_bytes: usize) -> Vec<u8> {
        let mut ret = vec![0; no_of_bytes as usize];
        let mut rng = rand::thread_rng();
        for i in 0..no_of_bytes - 1 {
            ret[i] = rng.gen();
        }
        ret
    }

    fn is_ecb_mode(input: &Vec<u8>) -> bool {
        let mut vector_set = std::collections::HashSet::new();
        let chunk_vector: Vec<_> = input.chunks(16).map(|c| c.to_vec()).collect();
        let chunk_vector_len = chunk_vector.len();
        vector_set.extend(chunk_vector.iter());

        if vector_set.len() < chunk_vector_len {
            true
        } else {
            false
        }
    }

    fn aes_ecb_128(key: &Vec<u8>, input_bytes: &Vec<u8>, encrypt: bool) -> Vec<u8> {
        let cipher = Cipher::aes_128_ecb();
        if encrypt {
            openssl::symm::encrypt(cipher, key, None, input_bytes.as_slice())
                .expect("Could not encrypt using AES ECB 128 Mode.")
        } else {
            openssl::symm::decrypt(cipher, key, None, input_bytes.as_slice())
                .expect("Could not decrypt using AES ECB 128 Mode.")
        }
    }

    fn aes_ecb_128_crypt(
        key: &Vec<u8>,
        input_bytes: &Vec<u8>,
        encrypt: Mode,
        pad: bool,
    ) -> Vec<u8> {
        let mut c = Crypter::new(Cipher::aes_128_ecb(), encrypt, key, None)
            .expect("Cannot create ECB Mode cipher.");
        let mut msg = vec![0; input_bytes.len() + Cipher::aes_128_ecb().block_size()];
        let mut count = 0;
        c.pad(pad);
        count += c
            .update(input_bytes, msg.as_mut_slice())
            .expect("Could not encrypt block.");
        count += c
            .finalize(msg.as_mut_slice())
            .expect("Could not finalize block.");
        msg.truncate(count);
        msg
    }

    fn remove_padding(mut plain_block: Vec<u8>) -> Vec<u8> {
        let last_byte = plain_block[plain_block.len() - 1];
        let num_bytes = last_byte as i32;
        if num_bytes >= 1 && num_bytes < 16 {
            plain_block.truncate(plain_block.len() - num_bytes as usize)
        }
        plain_block
    }

    fn aes_cbc_128_enc(key: &Vec<u8>, plaintext: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        let mut ret = vec![];
        let mut prev_block = iv.clone();
        let padded_plaintext = pad_bytes(
            plaintext.to_vec(),
            openssl::symm::Cipher::aes_128_ecb().block_size() as i32,
        );
        for i in padded_plaintext.chunks(16) {
            let xor_result = fixed_xor(i, prev_block.as_slice());
            let cipher_block = aes_ecb_128_crypt(key, &xor_result, Mode::Encrypt, false);
            ret.extend(cipher_block.iter());
            prev_block = cipher_block.clone();
        }
        ret
    }

    fn aes_cbc_128_dec(key: &Vec<u8>, ciphertext: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
        let mut ret = vec![];
        let mut prev_block = iv.clone();
        for i in ciphertext.chunks(16) {
            let cleartext_block = aes_ecb_128_crypt(key, &i.to_vec(), Mode::Decrypt, false);
            let plaintext_block = fixed_xor(cleartext_block.as_slice(), prev_block.as_slice());
            ret.extend(plaintext_block.iter());
            prev_block = i.to_vec().clone();
        }
        remove_padding(ret)
    }

    fn pad_bytes(i: Vec<u8>, no_of_bytes: i32) -> Vec<u8> {
        if i.len() % no_of_bytes as usize > 0 {
            let mut ret_vec: Vec<u8> = vec![];
            let bytes_to_add = no_of_bytes - (i.len() % no_of_bytes as usize) as i32;
            let additional_byte_char = char::from(bytes_to_add as u8);
            ret_vec.extend_from_slice(i.as_slice());
            for _j in 0..bytes_to_add {
                let mut buffer = [0; 1];
                ret_vec.extend_from_slice(additional_byte_char.encode_utf8(&mut buffer).as_ref());
            }
            ret_vec
        } else {
            i
        }
    }

    fn b64decode_to_vec(raw_file_contents: String) -> Vec<u8> {
        let b64_decode = match base64::decode(raw_file_contents.replace('\n', "").as_bytes()) {
            Err(_why) => panic!("Could not decode string into base64"),
            Ok(res) => res,
        };
        b64_decode
    }

    fn read_file_to_string(input_path: &str) -> String {
        let path = Path::new(input_path);
        let mut input = match File::open(&path) {
            Ok(file) => file,
            Err(why) => panic!("Could not open {}:{}", path.display(), why.description()),
        };
        let mut raw_file_contents = String::new();
        match input.read_to_string(&mut raw_file_contents) {
            Ok(_rez) => (),
            Err(e) => error!("Could not read file {}", e.description()),
        }
        raw_file_contents
    }

    #[derive(Debug, Clone)]
    struct ScoreResult {
        key: u8,
        score: usize,
        plaintext: Vec<u8>,
    }

    fn compute_hamming_distance(lhs: &[u8], rhs: &[u8]) -> u64 {
        let mut sum: u64 = 0;
        for (a, b) in lhs.iter().zip(rhs) {
            sum += (a ^ b).count_ones() as u64
        }
        sum
    }

    fn get_max_score_result(scores: &mut Vec<ScoreResult>) -> ScoreResult {
        scores.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));
        scores.reverse();
        scores[0].clone()
    }

    fn get_max_xor_score(target: Vec<u8>) -> ScoreResult {
        let magic = String::from("ETAOIN SHRDLU").to_ascii_lowercase();
        let mut score_map = HashMap::new();

        // Because I'm lazy and don't like typing. There must be a nicer way of doing this.
        let mut magic_len = magic.len();
        for b in magic.bytes() {
            score_map.insert(b, magic_len);
            magic_len -= 1;
        }

        let mut scores = Vec::new();
        for i in 0..255 {
            let xord_result = single_char_xor(target.borrow(), i);
            let curr_score = score(&xord_result, &score_map);
            scores.push(ScoreResult {
                key: i,
                plaintext: xord_result,
                score: curr_score,
            });
        }
        get_max_score_result(&mut scores)
    }

    fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter()
            .zip(b.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect_vec()
    }

    fn score(input_bytes: &Vec<u8>, score_map: &HashMap<u8, usize>) -> usize {
        let mut score = 0;
        for t in input_bytes {
            match score_map.get(&t) {
                Some(value) => score += value,
                None => score += 0,
            }
        }
        score
    }

    fn single_char_xor(b: &[u8], k: u8) -> Vec<u8> {
        let mut ret = Vec::new();

        for i in b.iter() {
            ret.push(i ^ k);
        }
        ret
    }

    fn get_buffered_lines(p: &Path) -> BufReader<File> {
        BufReader::new(File::open(p).expect("Could not open file."))
    }
}

extern crate pretty_env_logger;
#[macro_use] extern crate log;

fn main() {
    pretty_env_logger::init();
    info!("Run the tests !");
}
