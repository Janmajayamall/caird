**Background**

Throughout description of APIs, for ease, we will assume that there exists a single computing node $C$. However, in reality there will exist a threshold network of $n$ nodes with $t$ out $n$ access structure. Each computation is performed by each node in the network. 

For now we will also assume a threshold decryption procedure that decrypts a given array of ciphertexts and returns corresponding plaintexts
```
// run threshold decryption procedure for each ciphertext in ct and returns corresponding plaintexts
fn threshold_decrypt(ciphertexts: []) -> plaintexts
```

The decryption procedure in real life scenario should only work if $t$ out $n$ nodes are in consensus, but we will assume for now that they always are. Whenever we refer to $C$ as signing the output we are assuming that $t$ out $n$ nodes in $C_n$ are in consensus and sign the output. Whenever $C$ returns output and corresponding signature, we assume that a random leader $C_l$ is selected from $C_n$ and all nodes in consensus send their signature to $C_l$. $C_l$ collects all signature and packs signature and output into a data blob and posts it on-chain to the calling smart contract. 

We will use a signature aggegration scheme to aggregate signature into a single signautre for posting on-chain, but details of the scheme are irrelevant for this document. 

We don't discuss the failure case when less than t out of n nodes are in consensus. The behaviour is still undecided. 


**IsUnique**

Enables smart contract to retrieve an array consisting either 0 or 1, for input ciphertexts $cts = \{ct_1,ct_2,...,ct_n\}$ where bit 1 at index $i$ indicates uniquness, otherwise not. 

User inputs: 

Each user $u_i$ does the following: 
1. Encodes private input $p_i$ as FHE plaintext and encrypts it under $pk$ to produce $ct_i$.
2. Produces zk proof $\pi_i$ that proves (1) $p_i$ satisfies some arbitrary constraint set by smart contract and (2) $ct_i$ is correct encryption of $p_i$ under $pk$. In addition to other public inputs, $\pi_i$ should have $h_{cti} = Hash(ct_i)$ as one of its public inputs. 
3. Sends $\pi_i$, $h_{cti}$, and other related inputs to smart contract. Sends $ct_i$ to $C$.

Validity checks:

Consider the calling smart contract as $sc$. For each $ct_i$, $C$ verifies the following:
1. Corresponding proof $\pi_i$ exists in $sc$.
2. $C$ hashes $ct_i$ to produce $h_{cti}$ and verifies the proof $\pi_i$ with public input as $h_{cti}$ (along with other necessary public inputs required by $sc$). 
3. If proof is invalid in (2) then $C$ removes $ct_i$ from input ciphertext set. 

Checking in-equality:

Note that following statement is correct due to fermat's little theorem: 

$neq(x,y) = (x-y)^{p-1}$
outputs 1 if $x \neq y$ otherwise 0. 
where $x, y \in Z_p$ for some prime $p$


Checking uniqueness:

$C$ runs `is_unique` for each ciphertext in $cts$ and stores the result in `output` array. Notice that `output` array consists of has 1 at index $i$ is ciphertext $ct_i$ encrypts a unique value, otherwise 0.

```
function is_unique(u_i, cts):
    let unique_map = [];

    For u_j in users and u_i != u_j: 
        let is_neq = neq(u_i, u_j);
        unique_map.push(is_neq);

	// threahold decrypt can be delayed further until unique_map
	// is generated for each user u_i. This will reduce interaction. 
	let unique_map = threshold_decrypt(unique_map);
	
	// unique_map must consist of all 1s if user is unique
	let is_unique = 1;
	for bit in unique_map:
		is_unique &= bit;

return is_unique;
```

$C$ signs `output` as $sig$ and returns ($sig$, `output`)

Problems: 
1. Expand the API to support encrypting different data sizes in ciphertext.
	1. One suggestion is  to have variations of `isUnique` that support different data sizes.
2. In most cases smart contract will require users to prove some arbitrary constraint on encrypted private value. To make it easier for developer the circuit for proof of encryption must be modular such that developers can bind it with their existing circuit and simply add hash of ciphertext as an additional public input. Exact way to achieving this is still unclear. 

References: 


------

Select and Count

I have yet to figure out how to convert this to threshold

------

**Lass than function** 

**Univariate Less than**

$$LT(X,Y) = \frac{p+1}{2}(X-Y)^{p-1} + \sum_{i=1,odd}^{p-2} \alpha_i (X - Y)^i$$
where $\alpha_i$ is the $i_th$ coefficient of polynomial with degree $p-2$.
$$\alpha_i = \sum_{a = 1}^{\frac{p-1}{2}} a^{p - 1 - i}$$
Let $Z = X- Y$.
Notice that we can re-write
$$
\sum_{i=1,odd}^{p-2} \alpha_i (Z)^i
$$
using even powers as
$$
Z\sum_{i=0,even}^{p-3} \alpha_{i+1} (Z)^i
$$
Thus we collapse summation into a polynomial g(X) with X = Z^2 and of degree $=\frac{p-3}{2}$.
$$
g(X) = \sum_{i=0}^{\frac{p-3}{2}} \alpha_{(i\cdot 2)+1}X^i
$$
Thus we can re-write $LT$ as 
$$
LT(X,Y) = \frac{p+1}{2}Z^{p-1} + Zg(Z^2)
$$

We evaluate $g(Z^2)$ using Paterson-Stockmeyer to reduce non-scalar multiplications 

Few points to note: 
1. Univariate less than restricts the input range to $[-\frac{p-1}{2}, \frac{p-1}{2}]$
2. Since $Z = X - Y$ univariate $LT$ is equal to sign check function $IsNeg(X)$ that returns 1 if X < 0, otherwise 0. 


**Bivariate Less than**



---

Arbitrary function evqluation

------

Implement Sorting 

Developer can select the index to decrypt