use std::sync::Arc;

use bfv::{
    Ciphertext, Encoding, EvaluationKey, Evaluator, Modulus, Plaintext, PolyCache, PolyType,
    Representation, SecretKey,
};
use rand::thread_rng;
use utils::{decrypt_and_print, read_values, store_values};

pub mod utils;

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

pub fn sort(
    evaluator: &Evaluator,
    values: &[Ciphertext],
    ek: &EvaluationKey,
    sk: &SecretKey,
) -> Vec<Ciphertext> {
    let mut ht = vec![Ciphertext::placeholder(); values.len()];

    let one = evaluator.plaintext_encode(
        &vec![1; evaluator.params().degree],
        Encoding::simd(0, PolyCache::AddSub(Representation::Coefficient)),
    );

    for i in 0..values.len() {
        for j in 0..values.len() {
            if i < j {
                let lt = univariate_less_than(evaluator, &values[i], &values[j], ek, sk);

                let mut one_minus_lt = evaluator.negate(&lt);
                evaluator.add_assign_plaintext(&mut one_minus_lt, &one);

                // add lt to ht[i]
                if ht[i].c_ref().len() != 0 {
                    evaluator.add_assign(&mut ht[i], &lt);
                } else {
                    ht[i] = lt;
                }

                // add 1 - lt to ht[j]
                if ht[j].c_ref().len() != 0 {
                    evaluator.add_assign(&mut ht[j], &one_minus_lt);
                } else {
                    ht[j] = one_minus_lt;
                }
            }
        }
    }

    // equality checks

    // precompute powers
    let mut ht_powers = vec![];
    ht.iter().for_each(|c| {
        // change ciphertexts to Evaluation representation for plaintext multiplication
        let mut powers = powers_of_x(evaluator, c, 65536, sk, ek);
        powers.iter_mut().for_each(|c| {
            evaluator.ciphertext_change_representation(c, Representation::Evaluation);
        });
        ht_powers.push(powers);
    });

    let mut sorted_values = vec![];

    for i in 0..values.len() {
        // get `i_th` ciphertext in descending order
        sorted_values.push(sort_equality_subroutine(
            evaluator, i, &ht_powers, values, sk, ek,
        ));
    }

    sorted_values
}

/// Returns ciphertext with hamming weight = `i`
pub fn sort_equality_subroutine(
    evaluator: &Evaluator,
    i: usize,
    ht_powers: &[Vec<Ciphertext>],
    values: &[Ciphertext],
    sk: &SecretKey,
    ek: &EvaluationKey,
) -> Ciphertext {
    let p = 65537;
    let modp = &evaluator.params().plaintext_modulus_op;

    let one_pt = evaluator.plaintext_encode(
        &vec![1; evaluator.params().degree],
        Encoding::simd(0, PolyCache::AddSub(Representation::Evaluation)),
    );

    let n = values.len();
    let mut i_pow_k = 1;
    let mut sum = vec![Ciphertext::placeholder(); values.len()];
    for k in 0..p {
        // i^0 = 1, so we don't need plaintext multiplication
        if k == 0 {
            for j in 0..n {
                sum[j] = ht_powers[j][p - 1 - (k + 1)].clone();
            }
        } else if k == p - 1 {
            // x^((p-1)-(p-1)) = x^0 = 1; We can ignore the ciphertext
            // and add 1 depending on value of `i`.
            // Since `i^(p-1) = 1` if i!=0, and 0 otherwise, we add 1
            // to sum when i != 0.
            if i != 0 {
                for j in 0..n {
                    evaluator.add_assign_plaintext(&mut sum[j], &one_pt);
                }
            }
        } else {
            // if i == 0, then i^k == 0 for k > 0 always. Thus plaintext multiplication
            // will always result in 0 ciphertext. So skip this part when i==0.
            if i != 0 {
                let pt = evaluator.plaintext_encode(
                    &vec![i_pow_k; evaluator.params().degree],
                    Encoding::simd(0, PolyCache::Mul(PolyType::Q)),
                );
                for j in 0..n {
                    evaluator.add_assign(
                        &mut sum[j],
                        &evaluator.mul_plaintext(&ht_powers[j][p - 1 - (k + 1)], &pt),
                    );
                }
            }
        }

        i_pow_k = modp.mul_mod_fast(i_pow_k, i as u64);
    }

    // 1 - sum[j]
    for j in 0..n {
        evaluator.negate_assign(&mut sum[j]);
        evaluator.add_assign_plaintext(&mut sum[j], &one_pt);
    }

    // sum[j] indicates whether hw of `j^th` ciphertext equals `i`. It's
    // 1 if it does, otherwise 0. We multiply `j^th` ciphertext by `sum[j]` (which is 0 or 1).
    // Each product copies over values from `j^th` ct only if ct's hw is `i`.
    // Summation of all products should only contain values of ciphertexts corresponding to hw = `i`
    // \sum_{j=0}^{N-1} sum[j] * values[j]
    let mut sum_all = Ciphertext::placeholder();
    for j in 0..n {
        // Since `sum[j]` is in Evaluation form and `values[j]` is in Coefficient, pass
        // `sum[j]` as the first operand.
        let product = evaluator.mul_lazy(&sum[j], &values[j]);

        if j == 0 {
            sum_all = product;
        } else {
            evaluator.add_assign(&mut sum_all, &product);
        }
    }

    let res = evaluator.scale_and_round(&mut sum_all);
    evaluator.relinearize(&res, ek)
}

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
        let mut x_0_pt = None;
        let mut sum_m = Ciphertext::placeholder();
        for m_index in 0..181 {
            // degree of g(x) is (65537 - 3) / 2
            // dbg!(181 * k_index + m_index);
            if 181 * k_index + m_index <= ((65537 - 3) / 2) {
                let alpha = coefficients[(181 * k_index) + m_index];

                if m_index == 0 {
                    let pt_alpha = evaluator.plaintext_encode(
                        &vec![alpha; evaluator.params().degree],
                        Encoding::simd(0, PolyCache::AddSub(Representation::Evaluation)),
                    );
                    x_0_pt = Some(pt_alpha);
                } else {
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
        }

        if x_0_pt.is_some() {
            // ad x^0 to sum_m
            evaluator.add_assign_plaintext(&mut sum_m, &x_0_pt.unwrap());
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
    let z_gx = evaluator.mul_lazy(&sum_k, &z);

    // ((p+1)/2)z + z * g(z^2)
    evaluator.add_assign(&mut z_max_lazy, &z_gx);

    let res = evaluator.scale_and_round(&mut z_max_lazy);
    let res = evaluator.relinearize(&res, ek);

    res
}

/// \alpha_i = \sum_{a = 1}^{\frac{p-1}{2}} a^{p - 1 - i}
pub fn compute_lt_coefficients(t: u64) -> Vec<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bfv::BfvParameters;
    use rand::thread_rng;

    #[test]
    fn less_than_works() {
        let mut rng = thread_rng();

        let mut params = BfvParameters::new(&[60; 10], 65537, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);

        let modt_by_2 = Modulus::new(params.plaintext_modulus / 2);

        let sk = SecretKey::random_with_params(&params, &mut rng);
        let mx = modt_by_2.random_vec(params.degree, &mut rng);
        let my = modt_by_2.random_vec(params.degree, &mut rng);

        let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);

        let evaluator = Evaluator::new(params);

        let ptx = evaluator.plaintext_encode(&mx, Encoding::default());
        let pty = evaluator.plaintext_encode(&my, Encoding::default());
        let x = evaluator.encrypt(&sk, &ptx, &mut rng);
        let y = evaluator.encrypt(&sk, &pty, &mut rng);
        let res_ct = univariate_less_than(&evaluator, &x, &y, &ek, &sk);
        let res_m =
            evaluator.plaintext_decode(&evaluator.decrypt(&sk, &res_ct), Encoding::default());
        let expected = mx
            .iter()
            .zip(my.iter())
            .map(|(x, y)| if x < y { 1 } else { 0 })
            .collect::<Vec<u64>>();
        assert_eq!(res_m, expected);
    }

    #[test]
    fn sort_univariate_works() {
        let mut rng = thread_rng();

        let mut params = BfvParameters::new(&[60; 15], 65537, 1 << 4);
        params.enable_hybrid_key_switching(&[60; 3]);

        let sk = SecretKey::random_with_params(&params, &mut rng);

        let ek = EvaluationKey::new(&params, &sk, &[0], &[], &[], &mut rng);

        let evaluator = Evaluator::new(params);
        let max = 5;
        let modt_by_2 = Modulus::new(evaluator.params().plaintext_modulus / 2);
        let m_values = (0..max)
            .into_iter()
            .map(|_| modt_by_2.random_vec(evaluator.params().degree, &mut rng))
            .collect::<Vec<Vec<u64>>>();
        let values = m_values
            .iter()
            .map(|i| {
                let pt = evaluator.plaintext_encode(i, Encoding::default());
                evaluator.encrypt(&sk, &pt, &mut rng)
            })
            .collect::<Vec<Ciphertext>>();

        let sorted_values = sort(&evaluator, &values, &ek, &sk);
        dbg!(evaluator.measure_noise(&sk, &sorted_values[0]));

        let m_sorted = sorted_values
            .iter()
            .map(|c| evaluator.plaintext_decode(&evaluator.decrypt(&sk, &c), Encoding::default()))
            .collect::<Vec<Vec<u64>>>();

        // check
        let row_size = evaluator.params().degree;

        for row_index in 0..row_size {
            let mut row_values = vec![];
            let mut row_sorted = vec![];
            for col_index in 0..max {
                row_values.push(m_values[col_index][row_index]);
                row_sorted.push(m_sorted[col_index][row_index]);
            }

            row_values.sort_by(|a, b| b.cmp(a));

            assert_eq!(row_values, row_sorted);
        }
    }
}
