# Triage — aave-v3-core

| Finding ID | Detector | Severity | Line | Verdict | Note |
|------------|----------|----------|------|---------|------|
| `0b78b9a03e265827` | access-control | HIGH | contracts/protocol/tokenization/base/IncentivizedERC20.sol:122 | needs-triage |  |
| `0dd5958f4505bf6f` | access-control | HIGH | contracts/protocol/pool/Pool.sol:196 | needs-triage |  |
| `10c74847c9538553` | dos-loops | MEDIUM | contracts/misc/AaveOracle.sol:119 | needs-triage |  |
| `14d956fd41d8619f` | integer-overflow | MEDIUM | contracts/protocol/libraries/math/MathUtils.sol:23 | needs-triage |  |
| `212160a44783fd2f` | integer-overflow | MEDIUM | contracts/protocol/libraries/math/MathUtils.sol:50 | needs-triage |  |
| `216554b03d1e2de1` | dos-loops | LOW | contracts/protocol/pool/PoolConfigurator.sol:421 | needs-triage |  |
| `27858eed196657f4` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/GenericLogic.sol:254 | needs-triage |  |
| `27a21fbc12d3f621` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/ValidationLogic.sol:139 | needs-triage |  |
| `280f90f10ac2469c` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/GenericLogic.sol:221 | needs-triage |  |
| `416269fa3c978437` | access-control | HIGH | contracts/protocol/libraries/logic/PoolLogic.sol:38 | needs-triage |  |
| `4cb15b93047ea775` | dos-loops | MEDIUM | contracts/protocol/libraries/logic/PoolLogic.sol:84 | needs-triage |  |
| `50805d268680f0c7` | access-control | HIGH | contracts/protocol/libraries/aave-upgradeability/BaseImmutableAdminUpgradeabilityProxy.sol:69 | needs-triage |  |
| `565e4ff5d797fe01` | front-running | HIGH | contracts/protocol/pool/Pool.sol:196 | needs-triage |  |
| `5ccd8771f99bf5e2` | integer-overflow | MEDIUM | contracts/protocol/libraries/configuration/UserConfiguration.sol:221 | needs-triage |  |
| `6186210d4a4ef2da` | integer-overflow | MEDIUM | contracts/protocol/libraries/configuration/UserConfiguration.sol:103 | needs-triage |  |
| `61ed5b45026559cf` | timestamp-dependence | MEDIUM | contracts/protocol/libraries/logic/ReserveLogic.sol:71 | needs-triage |  |
| `73faf17fb6428f92` | timestamp-dependence | MEDIUM | contracts/protocol/libraries/logic/ReserveLogic.sol:93 | needs-triage |  |
| `793e2d9f5aefc9bf` | front-running | MEDIUM | contracts/protocol/tokenization/base/IncentivizedERC20.sol:137 | needs-triage |  |
| `7a63e45774a29253` | integer-overflow | MEDIUM | contracts/protocol/libraries/configuration/UserConfiguration.sol:49 | needs-triage |  |
| `855cdc0df31fb6d2` | dos-loops | MEDIUM | contracts/misc/AaveProtocolDataProvider.sol:40 | needs-triage |  |
| `94460c912e0e1e57` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/LiquidationLogic.sol:466 | needs-triage |  |
| `a1828e378e3a0b21` | flash-loan | MEDIUM | contracts/protocol/libraries/logic/LiquidationLogic.sol:285 | needs-triage |  |
| `a35e235b040d3417` | dos-loops | MEDIUM | contracts/protocol/libraries/logic/FlashLoanLogic.sol:70 | needs-triage |  |
| `a35e235b040d3417` | dos-loops | MEDIUM | contracts/protocol/libraries/logic/FlashLoanLogic.sol:70 | needs-triage |  |
| `a70248d04cc79281` | dos-loops | LOW | contracts/protocol/pool/PoolConfigurator.sol:324 | needs-triage |  |
| `b017949783e2f56c` | dos-loops | MEDIUM | contracts/misc/AaveProtocolDataProvider.sol:62 | needs-triage |  |
| `b1dc0c39fb18d642` | dos-loops | LOW | contracts/deployments/ReservesSetupHelper.sol:33 | needs-triage |  |
| `b49d68fbdeff4de7` | access-control | HIGH | contracts/protocol/tokenization/base/IncentivizedERC20.sol:143 | needs-triage |  |
| `b4da5702e1d2e623` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/GenericLogic.sol:64 | needs-triage |  |
| `b5d0b3023e70f275` | timestamp-dependence | MEDIUM | contracts/protocol/libraries/logic/ReserveLogic.sol:47 | needs-triage |  |
| `b69b8455600b5d3a` | dos-loops | LOW | contracts/protocol/pool/PoolConfigurator.sol:82 | needs-triage |  |
| `e4ea9d262094985a` | storage-collision | CRITICAL | contracts/protocol/configuration/PoolAddressesProvider.sol:15 | needs-triage |  |
| `e5559905b028df21` | integer-overflow | MEDIUM | contracts/protocol/libraries/logic/ValidationLogic.sol:662 | needs-triage |  |
| `ea48853dc9f622d9` | storage-collision | CRITICAL | contracts/protocol/libraries/aave-upgradeability/BaseImmutableAdminUpgradeabilityProxy.sol:16 | needs-triage |  |
| `eb65594f3ed8ff45` | front-running | HIGH | contracts/protocol/pool/Pool.sol:326 | needs-triage |  |
| `f5db5d794e095cff` | front-running | HIGH | contracts/protocol/pool/L2Pool.sol:43 | needs-triage |  |
| `f67921b6d1b17c1e` | front-running | HIGH | contracts/protocol/pool/L2Pool.sol:91 | needs-triage |  |
