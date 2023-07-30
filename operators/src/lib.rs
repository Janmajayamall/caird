use std::sync::Arc;

use bfv::{
    Ciphertext, Encoding, EvaluationKey, Evaluator, Modulus, Plaintext, PolyCache, PolyType,
    Representation, SecretKey,
};
use rand::thread_rng;
use utils::{decrypt_and_print, read_values, store_values};

pub mod utils;

/// Sqaures x repeatedly to calculate x..x^256
fn powers_of_x_bases(evaluator: &Evaluator, x: &Ciphertext) -> Vec<Ciphertext> {
    todo!()
}

pub fn powers_of_x(
    evaluator: &Evaluator,
    x: &Ciphertext,
    max: usize,
    sk: &SecretKey,
    ek: &EvaluationKey,
) -> Vec<Ciphertext> {
    let dummy = Ciphertext::new(vec![], PolyType::Q, 0);
    let mut values = vec![dummy; max];
    let mut calculated = vec![0u64; max];
    values[0] = x.clone();
    calculated[0] = 1;
    // let mut mul_count = 0;

    for i in (2..(max + 1)).rev() {
        let mut exp = i;
        let mut base_deg = 1;
        let mut res_deg = 0;

        while exp > 0 {
            if exp & 1 == 1 {
                let p_res_deg = res_deg;
                res_deg += base_deg;
                if res_deg != base_deg && calculated[res_deg - 1] == 0 {
                    let tmp = evaluator.mul(&values[p_res_deg - 1], &values[base_deg - 1]);
                    values[res_deg - 1] = evaluator.relinearize(&tmp, ek);
                    // println!("Res deg time: {:?}", now.elapsed());
                    calculated[res_deg - 1] = 1;
                    // mul_count += 1;
                }
            }
            exp >>= 1;
            if exp != 0 {
                let p_base_deg = base_deg;
                base_deg *= 2;
                if calculated[base_deg - 1] == 0 {
                    let tmp = evaluator.mul(&values[p_base_deg - 1], &values[p_base_deg - 1]);
                    values[base_deg - 1] = evaluator.relinearize(&tmp, ek);

                    calculated[base_deg - 1] = 1;

                    // mul_count += 1;
                }
            }
        }
    }
    // dbg!(mul_count);

    values
}

fn peterson_stockmeyer() {}

pub fn univariate_less_than(
    evaluator: &Evaluator,
    x: &Ciphertext,
    y: &Ciphertext,
    ek: &EvaluationKey,
    sk: &SecretKey,
) -> Ciphertext {
    let z = evaluator.sub(x, y);
    let z_sq = evaluator.relinearize(&evaluator.mul(&z, &z), ek);

    // z^2..(z^2)^181
    let mut m_powers = powers_of_x(evaluator, &z_sq, 181, sk, ek);
    // (z^2)^181..((z^2)^181)^181
    let k_powers = powers_of_x(evaluator, &m_powers[180], 181, sk, ek);

    // decrypt_and_print(evaluator, &m_powers[180], sk, "m_powers[180]");
    // decrypt_and_print(evaluator, &k_powers[180], sk, "k_powers[180]");

    // ((z^2)^181)^181 * (z^2)^7 = z^65536; z^{p-1}
    let mut z_max_lazy = evaluator.mul_lazy(&k_powers[180], &m_powers[6]);
    {
        // coefficient for z^65536 = (p+1)/2
        let pt = evaluator.plaintext_encode(
            &vec![32769; evaluator.params().degree],
            Encoding::simd(0, PolyCache::Mul(PolyType::PQ)),
        );
        evaluator.mul_poly_assign(&mut z_max_lazy, pt.mul_poly_ref());
    }

    // change m_powers to Evaluation representation for plaintext multiplications
    m_powers.iter_mut().for_each(|x| {
        evaluator.ciphertext_change_representation(x, Representation::Evaluation);
    });

    let coefficients = read_values("less_than.bin");

    // evaluate g(x), where x = z^2
    let mut left_over = Ciphertext::placeholder();
    let mut sum_k = Ciphertext::placeholder();
    for k_index in 0..182 {
        // m loop calculates x^0 + x + ... + x^181
        let mut sum_m = Ciphertext::placeholder();
        for m_index in 1..181 {
            // degree of g(x) is (65537 - 3) / 2
            // dbg!(181 * k_index + m_index);
            if 181 * k_index + m_index <= ((65537 - 3) / 2) {
                let alpha = coefficients[(181 * k_index) + m_index];
                let pt_alpha = evaluator.plaintext_encode(
                    &vec![alpha; evaluator.params().degree],
                    Encoding::simd(0, PolyCache::Mul(PolyType::Q)),
                );

                if m_index == 1 {
                    sum_m = evaluator.mul_poly(&m_powers[m_index - 1], pt_alpha.mul_poly_ref());
                } else {
                    evaluator.add_assign(
                        &mut sum_m,
                        &evaluator.mul_poly(&m_powers[m_index - 1], &pt_alpha.mul_poly_ref()),
                    );
                }
            }
        }

        if 181 * k_index + 0 <= ((65537 - 3) / 2) {
            // handle x^0
            let alpha = coefficients[(181 * k_index) + 0];
            let pt_alpha = evaluator.plaintext_encode(
                &vec![alpha; evaluator.params().degree],
                Encoding::simd(0, PolyCache::AddSub(Representation::Evaluation)),
            );
            evaluator.add_assign_plaintext(&mut sum_m, &pt_alpha);
        }

        if k_index == 0 {
            evaluator.ciphertext_change_representation(&mut sum_m, Representation::Coefficient);
            left_over = sum_m;
        } else {
            // `sum_m` is in Evaluation representation and k_powers is in Coefficient  so pass `sum_m` is first operand
            let product = evaluator.mul_lazy(&sum_m, &k_powers[k_index - 1]);
            if k_index == 1 {
                sum_k = product;
            } else {
                evaluator.add_assign(&mut sum_k, &product);
            }
        }
    }

    let mut sum_k = evaluator.relinearize(&evaluator.scale_and_round(&mut sum_k), ek);
    evaluator.add_assign(&mut sum_k, &left_over);

    // z * g(z^2)
    let mut z_gx = evaluator.mul_lazy(&sum_k, &z);

    // ((p+1)/2)z + z * g(z^2)
    evaluator.add_assign(&mut z_max_lazy, &z_gx);

    let res = evaluator.scale_and_round(&mut z_max_lazy);
    let res = evaluator.relinearize(&res, ek);

    res
}

/// \alpha_i = \sum_{a = 1}^{\frac{p-1}{2}} a^{p - 1 - i}
pub fn compute_coefficients(t: u64) -> Vec<u64> {
    let modt = Modulus::new(t);

    let mut alpha_vec = vec![];

    for i in 0..(t - 3 + 1) {
        // only when even
        if i & 1 == 0 {
            let mut alpha = 0;

            for a in 1..((t - 1) / 2) + 1 {
                alpha = modt.add_mod_fast(alpha, modt.exp(a, (t - 1 - (i + 1)) as usize));
            }
            alpha_vec.push(alpha);
        }
    }

    store_values(&alpha_vec, "less_than.bin");

    alpha_vec
}
