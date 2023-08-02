**Noise flooding**

To understand the basic problem with threshold FHE done naively consider the following LWE instance:
$$b = a \cdot s + \Delta m + e$$
that produces ciphertext as
$$(a, b) \space where \space a \in Z^l_q, b \in Z_q$$
Assume there exists a protocol for threshold decryption using which parties can reconstruct $a \cdot s$ to decrypt $(a,b)$ as
$$\Delta m + e = b - a\cdot s$$
and the scale down $\Delta m + e$ by $\Delta$ and round to find $m$.

But notice that this leaks the secret $s$. This is because any party individually, assuming correct decryption, can calculate $e$. Subsequently using ciphertext they can recover $s$.

To usual approach to avoid leaking secret $s$ during threshold decryption is to add noise (ie noise flooding). Instead of decryption procedure producing $a \cdot s$, it produces $a \cdot s + E$. Thus the decryption equation now becomes:
$$\Delta m + e + E = b - a\cdot s + E$$
As long as $e + E$ are below certain threshold scaling down $\Delta m + e + E$ by $\Delta$ result in correct decryption $m$.

Since a single party cannot reconstruct $E$, the point of adding $E$ is to mask $e$ sufficiently well that $e$ cannot be recovered. Thus, exists a trade off in size of $E$. $E$ should be big enough to mask $e$ but it should not be big enough such that $E + e$ flows in message space during decryption procedure.

**Size of $E$**

In [paper](https://eprint.iacr.org/2022/816) notion of separating computational security $\lambda$ (based on RLWE) from statistical security $s$ (adversary has $2^{-s}$ probability to recover $e$, thus the secret $s$) was introduced.

Formula for noise bits $\sigma$ ($E$ above) is given as
$$\sigma = \sqrt{ 2 * 4 * \alpha * n} * 2^{s/2}$$
where $\alpha$ is number of adversarial queries, $n$ is RLWE ring dimension and $s$ is statistical security.

Restricting $\alpha$ can he helpful. For example for statistical security of $s = 40$ and \alpha set to 2^10, \sigma = 34 bits. In case of blockchains, restricting \alpha can be easy.

In practice for BFV/BGV handling $E$ is quite easy. Care should be taken to have extra $\sigma$ bits in noise budget before performing threshold decryption procedure. It also does not degrades performance much since $\sigma$ bits of additional noise budget can be accommodated by adding atmost 1 level.

References:

1. https://crypto.stackexchange.com/questions/101010/how-to-choose-the-large-noise-when-using-noise-flooding-technique-in-fhe
2. https://openfhe.discourse.group/t/appropriate-error-parameters-for-the-noise-flooding/95
3. https://eprint.iacr.org/2023/815

**Shamir Secret Sharing**
TODO

**Threshold FHE**

Note that threshold schemes only provide passive security not active security. We will require zk proofs for active security. In other words, we will require parties to furnish their secret share protocol with zk proofs.

TODO

References

1. https://eprint.iacr.org/2022/780.pdf (builds on (2))
2. https://eprint.iacr.org/2020/304.pdf
3. https://eprint.iacr.org/2023/815
