**Background**

Throughout description of APIs, for ease, we will assume that there exists a single computing node $C$. However, in reality there will exist a threshold network of $n$ nodes with $t$ out $n$ access structure. Each computation is performed by each node in the network. 

For now we will also assume a threshold decryption procedure that decrypts a given array of ciphertexts and returns corresponding plaintexts
```
// run threshold decryption procedure for each ciphertext in ct and returns corresponding plaintexts
fn threshold_decrypt(ciphertexts: []) -> plaintexts
```

The decryption procedure in real life scenario should only work if $t$ out $n$ nodes are in consensus, but we will assume for now that they always are. Whenever we refer to $C$ as signing the output we are assuming that $t$ out $n$ nodes in $C_n$ are in consensus and sign the output. Whenever $C$ returns output and corresponding signature, we assume that a random leader $C_l$ is selected from $C_n$ and all nodes in consensus send their signature to $C_l$. $C_l$ collects all signature and packs signature and output into a data blob and posts it on-chain to the calling smart contract. 

We will use a signature aggregation scheme to aggregate signature into a single signature for posting on-chain, but details of the scheme are irrelevant for this document. 

We don't discuss the failure case when less than $t$ out of $n$ nodes are in consensus. The behaviour is still undecided. 


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

References: 


------

Select and Count

TODO - threshold

------

**Less than function** 

**Univariate Less than**

**User input**
TODO

**Output**
TODO

**Implementation**

$$LT(X,Y) = \frac{p+1}{2}(X-Y)^{p-1} + \sum_{i=1,odd}^{p-2} \alpha_i (X - Y)^i$$
where $\alpha_i$ is the $i_th$ coefficient of polynomial with degree $p-2$.
$$\alpha_i = \sum_{a = 1}^{\frac{p-1}{2}} a^{p - 1 - i}$$
Let $Z = X- Y$.
Notice that we can re-write
$$\sum_{i=1,odd}^{p-2} \alpha_i (Z)^i$$
using even powers as
$$Z\sum_{i=0,even}^{p-3} \alpha_{i+1} (Z)^i$$
Thus we collapse summation into a polynomial g(X) with X = Z^2 and of degree $=\frac{p-3}{2}$.
$$g(X) = \sum_{i=0}^{\frac{p-3}{2}} \alpha_{(i\cdot 2)+1}X^i$$
Thus we can re-write $LT$ as 
$$LT(X,Y) = \frac{p+1}{2}Z^{p-1} + Zg(Z^2)$$

We evaluate $g(Z^2)$ using Paterson-Stockmeyer to reduce non-scalar multiplications 

Few points to note: 
1. Univariate less than restricts the input range to $[-\frac{p-1}{2}, \frac{p-1}{2}]$
2. Since $Z = X - Y$ univariate $LT$ is equal to sign check function $IsNeg(X)$ that returns 1 if X < 0, otherwise 0. 


**Bivariate Less than**
TODO

--------
**Sort**

Sorts received ciphertexts set $ct = \{ct_0, ct_1, ..., ct_n\}$ of size $n$ and returns only necessary values. 

**User Input**
User encrypts its value under $pk$ to produce $ct_i$. User should also, in addition to other proofs required, produce a proof of correct encryption of $ct_i$ with public input set as $h_{cti} = Hash(ct_i)$. User must send proof $\pi_i$ and $h_{cti}$ to smart contract. User must send $ct_i$ to $C$.

**API arguments**
1. hamming_weight: If set to true then decrypts hamming weight of each ciphertext and returns them. For example, hamming weight of ciphertext with maximum value will be 0 and hamming weight of ciphertext with minimum value will be $n-1$
2. sort_index: By default an array with sorted values is returned. You can restrict to only reveal and return value at sort_index.

**Implementation**

Sorting uses less than as a sub routine. The basic idea is to use less than to construct comparison matrix $L$ for array $v$  such as: 

$$L_{i,j} = \left\{
\begin{array}{ll}
1 & \text{if v[i] < v[j]},\\
0 & \text{otherwise},\\
\end{array}
\right.$$

For ex, if $v = [1,2,3,4,5]$, then
$$L =
\begin{bmatrix} 
	0 & 1 & 1 & 1 & 1 \\
	0 & 0 & 1 & 1 & 1 \\
	0 & 0 & 0 & 1 & 1 \\
	0 & 0 & 0 & 0 & 1 \\
	0 & 0 & 0 & 0 & 0 \\
\end{bmatrix}$$
Notice that hamming weight (hw) of row corresponding to max value, ie 5, is 0 and hw of row corresponding to 4 is 1, and the pattern continues. In general, hamming weight of each row in $L$ will indicate corresponding value's position in descending ordered array. Thus, if original array is stored in descending order then the value at $i^{th}$ index will have hamming weight $i$ in $L$.

To sort array of ciphertexts $v = [ct_0,...,ct_n]$ we first calculate $L_j$, that is hamming weight of row corresponding to $ct_j$ in $L$. Notice that this results in $n$ ciphertexts as $[L_0, ... L_n]$. Now let $v'$ equal $v$ sorted in descending order. Then to get $i^{th}$ element of $v'$ we calculate: 
$$v'_i = \sum_{j=0}^{n-1} EQ(i, L_j) \cdot ct_j$$
where 
$$EQ(i,L_j) = 1 - (i - L_j)^{p-1}$$
$EQ$ can be simplified further so that cost of exponentiating $L_j$ can be amortised over different values of $i$ (only helpful if $EQ$ is called for multiple $i$ values). We can re-write $EQ$ as
$$EQ(i,L_j) = 1 - \sum_{k=0}^{p-1}  i^k L_j^{p-1-k}$$
Notice that $EQ(i, L_j)$ returns 1 if $i == L_j$ that is when hamming weight of $ct_j$ in $L == i$, 0 otherwise. Since hamming weight is unique , by multiplying $EQ(i, L_j)$ by $ct_j$ for each $j \in [0, n-1]$ and summing the products we obtain $i^{th}$ value.

In case hamming_weight is set true, threshold_decrypt $[L0, ...L_n]$ to produce hamming_weight array and return. 

If sort_index is set to $i$ then only extract $i^{th}$ element of $v'$ and return. Otherwise, extract all values of $v'$ and return. 

---

**Arbitrary function evaluation**

TODO

------
