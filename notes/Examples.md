# Example use-cases

Below are few use-cases describing how can you use FHE API calls to implement things in smart contracts that simply were not possible before. 

## Auctions
Auctions without leaking strategies are pretty hard to achieve on-chain. So let's see how can we build on-chain auctions using FHE APIs. 

Auctions on transparent chains like are Ethereum are somewhat limited by the fact that value transfers aren't private. Key issue is how do you make sure that bidder has enough balance to pay the bid upon winning. To get around this we have two options. (1) Ask users to commit to a maximum value to participate in auction and their bids cannot be more than the maximum value. (2) Use methods as implemented in [this](https://a16zcrypto.com/posts/article/hidden-in-plain-sight-a-sneaky-solidity-implementation-of-a-sealed-bid-auction/) and [this](https://ethglobal.com/showcase/anonymous-vickrey-auctions-on-chain-igh5e) using create2 to obscure bid commitments. For ease, I will use (1) but you can easily swap out (1) for (2).

Consider that auction contract $A$ is running vickery style auction for NFT. The nice feature of $A$ is that it allows the bids to be encrypted and only the second highest price to be revealed. For user $u_i$ to place bid $b_i$, it first needs to commit certain amount pre-defined by $A$ on-chain. This is make sure that $u_i$ has enough balance to cover their bid, in case they win. $u_i$ then encrypts their bid under $pk$ to produce $ct_{bi}$. $u_i$ then generates proof $\pi_i$ with public input $h_i = Hash(ct_{bi})$ that (a) proves their bid amount is less than pre-defined amount by $A$ and (b) proves that $ct_{bi}$ is correct encryption of bid amount under $pk$. $u_i$ then sends $\pi_i$, $h_i$ to $A$ and $ct_{bi}$ to $C$. 

Once bidding period ends. $A$ makes `Sort` API call to $C$ with `hamming_weight` set to `true` and `sort_index` set to `2`. $C$ first checks that all received $ct_{bi}$ tagged as $A$ are valid by checking their corresponding hash $h_i$ exists on-chain in $A$. $C$ then processes all received $ct_{bi}$s to produce `hamming_weight` array and `sort_value` as output. `hamming_weight` array contains rank of users according to the bids placed. For example, user with highest bid will have rank 0. `sort_value` is equal to the amount of second highest bid (since `sort_index` is set to 2). $C$ signs both output and sends them to $A$.

$A$ receives `hamming_weight` array and `sort_value`, then declares the user corresponding to `hamming_weight = 0` as winner and subtracts second highest bid amount (ie amount equal to `sort_value` ) from their committed funds. 

Notice that only the rank of each user in the auction and the second highest bid is revealed. 

With some modifications it is possible to only reveal identity of the user with highest bid (hint: requires an additional equality operation) without revealing the rank of each user. But explaining this is left as task for later. 

## Encrypted Votes

In [API](./API) we discussed how to have encrypted identities and prevent double votes. We can simply extend that to require encrypted votes as well. 

Each voter, in addition to encrypting $h = Hash(id)$, also encrypts their vote under $pk$ to produce $ct_{vi}$. Proof $\pi_i$ now also requires proof of correct encryption of $ct_{vi}$ and $h_{vi} = Hash(ct_vi)$ as a public input. User sends $\pi_i, h_{cti}, h_{vi}$ to $v_c$ and ct_{i},ct_{vi} to $C$.

Once voting period ends, $C$ first processes $ct_{i}$ as before to produce `values` array indicating whether $ct_i$ corresponds to an unique identity. $C$, instead of sending `values` directly to $v_c$ as before, uses it to tally votes. $C$ only adds $ct_{vi}$ corresponding to indices that have bit as 1 in `values` to produce $ct_{final}$. $C$ threshold decrypts $ct_{final}$, signs it, and sends vote tally to $v_c$. $v_c$ verifies the signature, accepts vote tally, and ends the voting round. 

## Simple Multi player game with encrypted shared state
TODO