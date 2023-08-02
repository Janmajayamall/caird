# Lifecycle of API call

To illustrate the life cycle of API, let's consider the following example. To ease reasoning we will think of threshold FHE network as a single FHE enabled node $C$. We will additionally assume that $C$ has made public its public key $pk$ using which anyone can encrypt message $m$ to $C$ under a given FHE scheme.

Smart contract is a voting smart contract $v_c$ and allows anyone to run a voting round. A voting round consists of two phases, (1) running phase during which anyone can cast a vote and (2) tally phase to tally total votes. $v_c$ has a really nice feature that it allows voters to stay anonymous while assuring that no one can cast double votes. This feature is enabled by leveraging $C$.

To vote user $u_i$ does the following:

1. Retrieves $pk$ of $C$.
2. Produces hash of their govt. id $h = Hash(id)$ and encrypts it using $pk$ to produce $ct_i$.
3. Produces a zk proof $\pi_i$ with public input $h_{cti} = Hash(ct_i)$ that proves (1) $id$ is a valid govt. id, (2) $h = Hash(id)$, and (3) $ct_i$ is correct encryption of $h$ using $pk$.

$u_i$ sends $\pi_i$, $h_{cti}$, and their vote $vote_i$ to $v_c$ on-chain. $u_i$ also sends $ct_i$ to $C$.

$v_c$ accepts $\pi_i$ and $h_{cti}$ only if $\pi_i$ is valid.

Once voting period ends, $v_c$ makes an `IsUnique` API call to $C$.

With `isUnique` API call, $C$ processes all received ciphertexts tagged as for $v_c$ and produces an array of bits `values` where bit at index $i$ indicates whether $ct_i$ is unique among all received ciphertexts.

Once processing is done $C$ signs `values` to produce signature $sig_c$ and sends both `values` and $sig_c$ on-chain to $v_c$.

Upon receiving `values` and $sig_c$, $v_c$ verifies $sig_c$ and then processes `values` to tally votes. To tally votes $v_c$ only counts votes corresponding to index $i$ at which `values[i] = 1`. After tallying votes, $v_c$ stores the result and ends the voting round.

Notice that by using $C$, $v_c$ was able to remove duplicate votes while assuring that voter identity remained anonymous.

TODO: Add a diagram
