use std::mem::swap;

pub enum FeistelMode {
    Encrypt,
    Decrypt,
}

pub fn feistel(
    data: &[u8],
    key: &[u8],
    rounds: u32,
    mode: FeistelMode,
) -> std::result::Result<Vec<u8>, ()> {
    let block_size = key.len() * 2;
    let mut result = vec![0 as u8; 0];
    for block in data.chunks(block_size) {
        let mut block = block.to_vec();
        if block.len() < block_size {
            pad_block(&mut block, block_size);
        }
        let l = &mut vec![0 as u8; block_size / 2];
        let r = &mut vec![0 as u8; block_size / 2];
        l[..key.len()].copy_from_slice(&block[0..block_size / 2]);
        r[..key.len()].copy_from_slice(&block[block_size / 2..block_size]);
        let iterate_slice = match mode {
            FeistelMode::Encrypt => (0..rounds).collect::<Vec<u32>>(),
            FeistelMode::Decrypt => (0..rounds).rev().collect::<Vec<u32>>()
        };
        for round_idx in iterate_slice {
            let r_dash = f(r, round_key(key, round_idx));
            (*l).iter_mut()
                .zip((*r_dash).iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
            swap(l, r);
        }
        swap(l, r);
        result.append(l);
        result.append(r);
    }
    Ok(result)
}

fn f(data: &[u8], round_key: &[u8]) -> Vec<u8> {
    (*data)
        .iter()
        .zip(round_key.iter())
        .map(|(&data_byte, &key_byte)| (data_byte + 1) ^ key_byte)
        .collect::<Vec<u8>>()
}

fn round_key(key: &[u8], _round_idx: u32) -> &[u8] {
    key
}

fn pad_block<'a>(block: & mut Vec<u8>, to_len: usize) {
    block.append(&mut vec![0 as u8; to_len - block.len()]);
}

#[cfg(test)]
mod tests {
    use super::{feistel, FeistelMode};
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn enc_dec_1_block() {
        match feistel(
            "HALLO WELT!!".as_bytes(),
            "AAAAAA".as_bytes(),
            16,
            FeistelMode::Encrypt,
        ) {
            Ok(enc) => {
                let dec_res = feistel(&enc, "AAAAAA".as_bytes(), 16, FeistelMode::Decrypt).unwrap();
                assert_eq!(
                std::str::from_utf8(
                    &dec_res
                )
                .unwrap(),
                "HALLO WELT!!"
            )
            },
            Err(_) => panic!("I'm sad"),
        };
    }

    #[test]
    fn enc_dec_moar_blockz() {
        let secret_message = "This is a really secret message containing all hidden secrets of world history. Nobody should read it ever!";
        let secret_key = "123456".as_bytes();
        match feistel(
            secret_message.as_bytes(),
            secret_key,
            16,
            FeistelMode::Encrypt,
        ) {
            Ok(enc) => {
                let dec_res = feistel(&enc, secret_key, 16, FeistelMode::Decrypt).unwrap();
                assert_eq!(
                std::str::from_utf8(
                    &dec_res
                )
                .unwrap().trim_end_matches('\0'),
                secret_message
            )
            },
            Err(_) => panic!("I'm sad"),
        };
    }

}
