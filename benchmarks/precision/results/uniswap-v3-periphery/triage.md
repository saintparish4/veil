# Triage — uniswap-v3-periphery

| Finding ID | Detector | Severity | Line | Verdict | Note |
|------------|----------|----------|------|---------|------|
| `00ce1e84d52c4b4c` | integer-overflow | HIGH | contracts/libraries/NFTDescriptor.sol:85 | needs-triage |  |
| `00d708b6c3d87ee4` | front-running | HIGH | contracts/lens/Quoter.sol:38 | needs-triage |  |
| `0b6ab4e3ca35d6da` | unchecked-erc20 | HIGH | contracts/V3Migrator.sol:42 | needs-triage |  |
| `10b686a2e200cffc` | integer-overflow | HIGH | contracts/NonfungiblePositionManager.sol:198 | needs-triage |  |
| `327b1be5ea59f23b` | flash-loan | HIGH | contracts/lens/Quoter.sol:38 | needs-triage |  |
| `4a5a5d12bf5bbfee` | integer-overflow | HIGH | contracts/libraries/HexStrings.sol:21 | needs-triage |  |
| `4a70533ca91fc2d6` | integer-overflow | HIGH | contracts/libraries/NFTSVG.sol:306 | needs-triage |  |
| `5230bc24bc6ffc16` | front-running | HIGH | contracts/base/LiquidityManagement.sol:25 | needs-triage |  |
| `52a60313bb9b39ee` | integer-overflow | HIGH | contracts/libraries/NFTSVG.sol:352 | needs-triage |  |
| `56e28ad98375be00` | integer-overflow | HIGH | contracts/libraries/HexStrings.sol:9 | needs-triage |  |
| `5d2d2741dd7119d8` | unchecked-calls | MEDIUM | contracts/base/PeripheryPayments.sol:61 | needs-triage |  |
| `5e5126a6eb110969` | integer-overflow | HIGH | contracts/libraries/PoolTicksCounter.sol:11 | needs-triage |  |
| `60d3b9efb28241a0` | unchecked-erc20 | HIGH | contracts/base/PeripheryPayments.sol:61 | needs-triage |  |
| `7c63be15807481c9` | integer-overflow | HIGH | contracts/NonfungiblePositionManager.sol:257 | needs-triage |  |
| `7de9b8bf0c26511c` | flash-loan | HIGH | contracts/examples/PairFlash.sol:46 | needs-triage |  |
| `876fa12cf63b6ada` | integer-overflow | HIGH | contracts/SwapRouter.sol:87 | needs-triage |  |
| `8c018f137a41405b` | integer-overflow | HIGH | contracts/lens/UniswapInterfaceMulticall.sol:27 | needs-triage |  |
| `8d781247cb988220` | dos-loops | HIGH | contracts/base/Multicall.sol:11 | needs-triage |  |
| `8d781247cb988220` | dos-loops | HIGH | contracts/base/Multicall.sol:11 | needs-triage |  |
| `912d351f9d28bb6c` | integer-overflow | HIGH | contracts/lens/TickLens.sol:12 | needs-triage |  |
| `9babfc75f1dca8cb` | flash-loan | HIGH | contracts/SwapRouter.sol:57 | needs-triage |  |
| `a18e7df6e0606726` | integer-overflow | HIGH | contracts/lens/QuoterV2.sol:123 | needs-triage |  |
| `a28c126970aa9488` | flash-loan | HIGH | contracts/lens/QuoterV2.sol:41 | needs-triage |  |
| `aa3bc3af7e0cd254` | front-running | HIGH | contracts/SwapRouter.sol:57 | needs-triage |  |
| `aaaaa2b5ddc0a758` | integer-overflow | HIGH | contracts/SwapRouter.sol:169 | needs-triage |  |
| `b2b32a2b12fb05fb` | access-control | HIGH | contracts/base/Multicall.sol:11 | needs-triage |  |
| `b4380a25e6c46fe6` | integer-overflow | HIGH | contracts/libraries/LiquidityAmounts.sol:23 | needs-triage |  |
| `b6e5a1e569dc5528` | front-running | HIGH | contracts/lens/QuoterV2.sol:41 | needs-triage |  |
| `bae0a0b1582cd2ba` | reentrancy | HIGH | contracts/base/Multicall.sol:14 | needs-triage |  |
| `bbb6f0d89891eb2c` | dos-loops | HIGH | contracts/lens/UniswapInterfaceMulticall.sol:27 | needs-triage |  |
| `bbb6f0d89891eb2c` | dos-loops | HIGH | contracts/lens/UniswapInterfaceMulticall.sol:27 | needs-triage |  |
| `bfd9d1c0331b14f7` | integer-overflow | HIGH | contracts/libraries/LiquidityAmounts.sol:82 | needs-triage |  |
| `cf2bbf78d7b3fad6` | flash-loan | HIGH | contracts/libraries/CallbackValidation.sol:15 | needs-triage |  |
| `d8c2a88778634582` | integer-overflow | HIGH | contracts/libraries/PoolTicksCounter.sol:88 | needs-triage |  |
| `e0bf7438f5c444cf` | integer-overflow | HIGH | contracts/lens/QuoterV2.sol:230 | needs-triage |  |
| `e5f82b773a521577` | integer-overflow | HIGH | contracts/lens/QuoterV2.sol:197 | needs-triage |  |
| `e96888b2ccc2011d` | access-control | HIGH | contracts/base/PoolInitializer.sol:13 | needs-triage |  |
| `f32e12f0edbacc7e` | integer-overflow | HIGH | contracts/lens/QuoterV2.sol:153 | needs-triage |  |
| `f3fb8b8485533b9a` | reentrancy | HIGH | contracts/lens/UniswapInterfaceMulticall.sol:34 | needs-triage |  |
| `f425004945df3951` | flash-loan | HIGH | contracts/base/LiquidityManagement.sol:25 | needs-triage |  |
| `fc5933d71ad4ee55` | integer-overflow | HIGH | contracts/NonfungiblePositionManager.sol:309 | needs-triage |  |
| `fd6d9b9a6b3bad5c` | integer-overflow | HIGH | contracts/libraries/NFTSVG.sol:402 | needs-triage |  |
