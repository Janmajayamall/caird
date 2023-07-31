# Caird

The repository consists of implementation details to bring FHE computation to existing smart contract.

In short, the concept is to enable smart contracts to leverage FHE computations though an API call. FHE computations will be performed on a separate threshold FHE layer. 

Contrary to most people thinking FHE as too far away, it is possible to write optimised FHE circuits for many widely use operations. For ex, apart from basic arithmetic, Sorting, Select+Count, Equality, RangeCheck, Arbitrary function evaluation, etc. The run-time of FHE circuits will depend on input size, but it still isn't too long to be considered infeasible. Keeping this in mind we are trying to answer the question of how to bring FHE computations to *existing* smart contract ecosystems. 

If you would like to leverage FHE for any of your on-chain application, please feel free to start a discussion/open an issue. This will help us design an API for the use-case and subsequently generalise it for other applications. The plan is to take an iterative approach so that we are able provide optimised FHE computation for specific use-cases and then over time generalise them for other use-cases. 

You can find (very much in progress) implementation notes [here](./notes/)  and prototype of API operators [here](./operators/). 
