use bfv::{Ciphertext, Encoding, Evaluator, SecretKey};
use byteorder::{ByteOrder, LittleEndian};
use std::{
    fmt::format,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

pub fn store_values(values: &[u64], file_name: &str) {
    let mut buf = vec![0u8; values.len() * 8];
    LittleEndian::write_u64_into(&values, &mut buf);

    let output_dir = Path::new("./data");
    std::fs::create_dir_all(output_dir).expect("Create ./data failed");
    let mut file_path = PathBuf::from(output_dir);
    file_path.push(file_name);
    let mut f = std::fs::File::create(file_path).unwrap();
    f.write_all(&buf).unwrap();
}

pub fn read_values(file_name: &str) -> Vec<u64> {
    let full_path = format!("./data/{file_name}");
    let bytes = std::fs::read(full_path).expect("{full_path} not found");
    let mut coeffs = vec![0u64; bytes.len() / 8];
    LittleEndian::read_u64_into(&bytes, &mut coeffs);
    coeffs.to_vec()
}

pub fn decrypt_and_print(evaluator: &Evaluator, ct: &Ciphertext, sk: &SecretKey, tag: &str) {
    let m = evaluator.plaintext_decode(&evaluator.decrypt(sk, ct), Encoding::default());
    println!("{tag} m: {:?}", m);
}

pub fn convert_u64_to_i64(values: &[u64], modq: u64) -> Vec<i64> {
    let q_by_2 = modq / 2;

    values
        .iter()
        .map(|v| {
            if *v < q_by_2 {
                *v as i64
            } else {
                -1 * (modq - *v) as i64
            }
        })
        .collect()
}
