use bfv::{BfvParameters, Encoding, EvaluationKey, Evaluator, Modulus, SecretKey};
use operators::{compute_coefficients, univariate_less_than};
use rand::thread_rng;

fn main() {
    let t = 65537;
    // let coeffs = compute_coefficients(t);
    // return;

    let mut rng = thread_rng();
    let mut params = BfvParameters::new(&[60; 10], t, 1 << 3);
    params.enable_hybrid_key_switching(&[60; 3]);

    let modt_by_2 = Modulus::new(32768);

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
    dbg!(evaluator.measure_noise(&sk, &res_ct));
    let res_m = evaluator.plaintext_decode(&evaluator.decrypt(&sk, &res_ct), Encoding::default());
    dbg!(mx, my);
    dbg!(res_m);
}
